#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
using namespace std;

unordered_map<string, int> isLogged; // 1->loggedIn 0->LoggedOut
unordered_map<string, string> cred;  // storing credentials <userid,password>
unordered_map<string, string> usernameToPort;
unordered_map<string, bool> groups;                                          // if group is there --> <groupid,true>
unordered_map<string, string> groupAdmin;                                    // group admin --> <groupid, admin>
unordered_map<string, unordered_set<string>> groupMembers;                   // set used because redundent entries can be there
unordered_map<string, unordered_set<string>> grpPendingRequests;             //<groupid, {userids}>
unordered_map<string, unordered_map<string, unordered_set<string>>> seeders; // groupid -> {map of filenames -> peer address}
unordered_map<string, string> fileSize;                                      // filename->size
unordered_map<string, string> hashofPieces;
string logFile, t1_ip, t2_ip, cur_IP_of_Tracker;
int t1_port, t2_port, cur_Port_of_Tracker;

vector<string> stringCut(string add, char point)
{
    vector<string> ans;

    int i = 0;
    while (i < add.size())
    {
        if (add[i] == point)
        {
            string temp = add.substr(0, i);
            ans.push_back(temp);
            add = add.substr(i + 1);
            i = 0;
        }
        else
        {
            i++;
        }
    }

    if (add.size() > 0)
    {
        ans.push_back(add);
    }

    return ans;
}

void joinThreads(vector<thread> &threads)
{
    for (thread &t : threads)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
}

void logWrite(const string &text)
{
    FILE *file = fopen(logFile.c_str(), "a"); // "a" opens the file for appending

    if (file == nullptr)
    {
        std::cerr << "Error opening log file: " << logFile << std::endl;
        return;
    }

    fprintf(file, "%s\n", text.c_str());
    fclose(file);
}

bool pathisPresent(const string &st)
{
    struct stat buff;
    return (stat(st.c_str(), &buff) == 0);
}

vector<string> readfile(char *path)
{
    const char *filename = path; // Change this to your file's name
    vector<string> lines;

    // Open the file using open system call
    int fileDescriptor = open(filename, O_RDONLY);

    if (fileDescriptor == -1)
    {
        perror("Error opening file");
        return lines;
    }

    char buffer[4096]; // Buffer to store data from the file
    string currentLine;
    ssize_t bytesRead;

    while ((bytesRead = read(fileDescriptor, buffer, sizeof(buffer))) > 0)
    {
        for (ssize_t i = 0; i < bytesRead; i++)
        {
            if (buffer[i] == '\n')
            {
                // Found a newline character, so store the current line
                lines.push_back(currentLine);
                currentLine.clear();
            }
            else
            {

                currentLine.push_back(buffer[i]);
            }
        }
    }

    if (!currentLine.empty())
    {
        lines.push_back(currentLine);
    }

    // Close the file
    close(fileDescriptor);

    return lines;
}

void *exitFunction(void *arg)
{
    for (;;)
    {
        string inputline;
        getline(cin, inputline);
        if (inputline == "quit")
        {
            exit(0);
        }
    }
}

void commandFunctions(int clientSocket)
{
    // will have all the commands calls
    string clientGroupID = "";
    string clientUserID = "";
    string CS = to_string(clientSocket);
    logWrite("--thread stated for client " + CS + "--");

    for (;;)
    {
        char input[2048];
        for (int i = 0; i < 2048; i++)
        {
            input[i] = 0;
        }

        if (read(clientSocket, input, 2048) <= 0)
        {
            isLogged[clientUserID] = 0;
            close(clientSocket);
            break;
        }

        logWrite("client request:" + string(input));

        string s;
        string inp = string(input);
        vector<string> rec_input;
        stringstream ss(inp);

        while (ss >> s)
        {
            rec_input.push_back(s);
        }

        if (rec_input[0] == "create_user")
        {
            if (rec_input.size() == 3)
            {
                bool b = false;
                string userID = rec_input[1];
                string pass = rec_input[2];

                if (cred.find(userID) != cred.end())
                {
                    b = true;
                }
                else
                {
                    cred[userID] = pass;
                }

                if (b == false)
                {
                    write(clientSocket, "Created Account", 15);
                }
                else
                {
                    write(clientSocket, "User Exists", 11);
                }
            }
            else
            {
                string temp = "Invalid number of arguments";
                int temp_size = temp.size();
                write(clientSocket, "Invalid number of arguments", temp_size);
            }
        }
        else if (rec_input[0] == "login")
        {
            if (rec_input.size() == 3)
            {
                int right = 5; // random
                string USERID = rec_input[1];
                string PASS = rec_input[2];

                if (cred.find(USERID) == cred.end()) // userid not created
                {
                    right = -1;
                }
                else if (cred[USERID] != PASS) // password is wrong
                {
                    right = -1;
                }

                if (right == 5 && isLogged.find(USERID) == isLogged.end()) // not logged in
                {
                    isLogged[USERID] = 1;
                    right = 0;
                }
                else if (right == 5)
                {
                    if (isLogged[USERID]) // logged in
                    {
                        right = 1;
                    }
                    else // logged out of session
                    {
                        isLogged[USERID] = 1;
                        right = 0;
                    }
                }

                if (right < 0)
                {
                    write(clientSocket, "Username or Password is not correct", 36);
                }
                else if (right > 0)
                {
                    write(clientSocket, "Already Logged in", 18);
                }
                else
                {
                    write(clientSocket, "Login Successful", 17);
                    clientUserID = rec_input[1];

                    char buff[100];
                    read(clientSocket, buff, 100); // get client Address from tracker

                    string clientAddress = string(buff);
                    usernameToPort[clientUserID] = clientAddress;
                }
            }
            else
            {
                string temp = "Invalid number of arguments";
                int temp_size = temp.size();
                write(clientSocket, "Invalid number of arguments", temp_size);
            }
        }
        else if (rec_input[0] == "logout")
        {
            if (isLogged[clientUserID] == true)
            {
                isLogged[clientUserID] = false;
                write(clientSocket, "Logout Success", 15);
                logWrite("logged out\n");
            }
            else
            {
                write(clientSocket, "Already Logged Out", 19);
                logWrite("Already Logged Out\n");
            }
        }
        else if (rec_input[0] == "create_group")
        {
            int result = 0;
            if (rec_input.size() == 2)
            {
                string groupid = rec_input[1];

                if (groups[groupid] == true)
                {
                    result = 1; // group is already there
                }

                if (result == 0) // created group
                {
                    groupAdmin[groupid] = clientUserID;
                    groups[groupid] = true;
                    groupMembers[groupid].insert(clientUserID);
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
                result = -1; // Invalid number of argumnets
            }

            if (result == 0)
            {
                clientGroupID = rec_input[1];
                write(clientSocket, "Group Successfully Created", 27);
            }
            else if (result == 1)
            {
                write(clientSocket, "Group Already Exists", 21);
            }
        }
        else if (rec_input[0] == "join_group")
        {
            if (rec_input.size() == 2)
            {
                logWrite("Join Group");

                if (groups.find(rec_input[1]) == groups.end())
                {
                    write(clientSocket, "Invalid Group ID", 17);
                }
                else if (groupMembers[rec_input[1]].find(clientUserID) != groupMembers[rec_input[1]].end())
                {
                    write(clientSocket, "Already in Group", 17);
                }
                else
                {
                    grpPendingRequests[rec_input[1]].insert(clientUserID);
                    write(clientSocket, "Group Request Sent", 19);
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "leave_group")
        {
            if (rec_input.size() == 2)
            {
                write(clientSocket, "Leaving group!!", 16);
                string ele = rec_input[1];
                if (groupAdmin.find(ele) == groupAdmin.end())
                {
                    write(clientSocket, "Invalid GroupID", 16);
                }
                else if (groupMembers[ele].find(clientUserID) != groupMembers[ele].end())
                {
                    if (groupAdmin[ele] == clientUserID)
                    {
                        write(clientSocket, "You are the admin", 18);
                    }
                    else
                    {
                        groupMembers[ele].erase(clientUserID);
                        write(clientSocket, "Group left", 11);
                    }
                }
                else
                {
                    write(clientSocket, "You are not in the group", 25);
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "list_requests")
        {
            if (rec_input.size() == 2)
            {
                string ele = rec_input[1];

                if (groupAdmin.find(ele) == groupAdmin.end() || groupAdmin[ele] != clientUserID)
                {
                    write(clientSocket, "You are not Admin", 18);
                }
                else if (grpPendingRequests[ele].size() == 0)
                {
                    write(clientSocket, "No Requests", 12);
                }
                else
                {
                    string reply = "";
                    logWrite("number of peding requests ->" + to_string(grpPendingRequests[ele].size()));

                    for (auto i = grpPendingRequests[ele].begin(); i != grpPendingRequests[ele].end(); i++)
                    {
                        reply += string(*i) + "\n";
                    }

                    write(clientSocket, &reply[0], reply.length());
                    logWrite("reply is " + reply);
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "accept_request")
        {
            if (rec_input.size() != 3)
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
            else
            {
                string ele = rec_input[1];
                string ele2 = rec_input[2];
                write(clientSocket, "Accepting Group requests", 25);

                if (groupAdmin.find(ele)->second == clientUserID)
                {
                    logWrite("Requests that are pending are:\n");

                    for (auto i : grpPendingRequests[ele])
                    {
                        logWrite(i);
                    }

                    grpPendingRequests[ele].erase(ele2);
                    groupMembers[ele].insert(ele2);

                    write(clientSocket, "Request Accepted", 17);
                }
                else
                {
                    write(clientSocket, "Only Admin can accept group requests, You are not the admin", 60);
                }
            }
        }
        else if (rec_input[0] == "list_groups")
        {
            if (rec_input.size() == 1)
            {
                if (groups.size() == 0)
                {
                    write(clientSocket, "No groups found !!", 19);
                }

                string rep = "List of all the groups:\n";
                for (auto z : groups)
                {
                    rep += z.first + "\n";
                }

                write(clientSocket, &rep[0], rep.length());
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "list_files")
        {
            if (rec_input.size() == 2)
            {
                string ele = rec_input[1];
                write(clientSocket, "Fetching files !!", 18);

                if (groupAdmin.find(ele) == groupAdmin.end())
                {
                    write(clientSocket, "Invalid GROUPID", 16);
                }
                else if (seeders[ele].size() == 0)
                {
                    write(clientSocket, "No files are found in the Group", 32);
                }
                else
                {
                    string rep = "";

                    for (auto i : seeders[rec_input[1]])
                    {
                        rep += i.first + "\n";
                    }

                    int replen = rep.size();
                    rep = rep.substr(0, replen - 1);
                    logWrite("list of files are -->" + rep);

                    write(clientSocket, &rep[0], rep.length());
                }
            }

            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "show_downloads")
        {
            write(clientSocket, "Output", 7);
        }
        else if (rec_input[0] == "stop_share")
        {
            if (rec_input.size() == 3) // remaining
            {
                string ele = rec_input[1];
                if (groupAdmin.find(ele) == groupAdmin.end())
                {
                    write(clientSocket, "Invalid GROUPID", 16);
                }
                else if (seeders[ele].find(rec_input[2]) == seeders[ele].end())
                {
                    write(clientSocket, "File not shared", 16);
                }
                else
                {
                    //
                    seeders[ele][rec_input[2]].erase(clientUserID);
                    if (seeders[ele][rec_input[2]].size() == 0)
                    {
                        seeders[ele].erase(rec_input[2]);
                    }

                    write(clientSocket, "Done", 5);
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
                return;
            }
        }
        else if (rec_input[0] == "upload_file")
        {
            if (rec_input.size() == 3)
            {
                string in1 = rec_input[1];
                string in2 = rec_input[2];
                if (groupMembers.find(in2) == groupMembers.end())
                {
                    write(clientSocket, "Error 1:", 9);
                }
                else if (groupMembers[in2].find(clientUserID) == groupMembers[in2].end())
                {
                    write(clientSocket, "Error 2:", 9);
                }
                else if (pathisPresent(in1) == false)
                {
                    write(clientSocket, "Error 3:", 9);
                }
                else
                {
                    char fileDet[524288];
                    for (int i = 0; i < 524288; i++)
                    {
                        fileDet[i] = 0;
                    }

                    write(clientSocket, "Uploading", 10);
                    logWrite("Uploading File");

                    if (read(clientSocket, fileDet, 524288))
                    {
                        if (string(fileDet) != "error") // this is imp
                        {
                            vector<string> fldet = stringCut(string(fileDet), '$');
                            vector<string> temp = stringCut(fldet[0], '/');
                            int size = temp.size();

                            string nameofFile = temp[size - 1];

                            string hashs = "";
                            for (int i = 4; i < fldet.size(); i++)
                            {
                                hashs += fldet[i];
                                if (i != fldet.size() - 1)
                                {
                                    hashs += "$";
                                }
                            }
                            hashofPieces[nameofFile] = hashs;

                            if (seeders[in2].find(nameofFile) == seeders[in2].end())
                            {
                                seeders[in2].insert({nameofFile, {clientUserID}});
                            }
                            else
                            {
                                seeders[in2][nameofFile].insert(clientUserID);
                            }

                            fileSize[nameofFile] = fldet[2];
                            write(clientSocket, "File is Uploaded", 17);
                        }
                        else
                        {
                            return;
                        }
                    }
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "list_files")
        {
            if (rec_input.size() == 2)
            {
                write(clientSocket, "Fetching the files", 19);

                if (groups.find(rec_input[1]) == groups.end())
                {
                    write(clientSocket, "Invalid GroupID", 16);
                }
                else if (seeders[rec_input[1]].size() == 0)
                {
                    write(clientSocket, "No files in Group", 18);
                }
                else
                {
                    string reply = "List of files: \n";

                    for (auto i : seeders[rec_input[1]])
                    {
                        reply += i.first + "\n";
                    }
                    write(clientSocket, &reply, reply.length());
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else if (rec_input[0] == "download_file")
        {
            if (rec_input.size() == 4)
            {
                string ele = rec_input[1];
                if (groupMembers.find(ele) == groupMembers.end())
                {
                    write(clientSocket, "Error 101:", 11);
                }
                else if (groupMembers[ele].find(clientUserID) == groupMembers[ele].end())
                {
                    write(clientSocket, "Error 102:", 11);
                }
                else
                {
                    bool b;
                    struct stat tempBuff;
                    if (stat(rec_input[3].c_str(), &tempBuff) == 0)
                    {
                        b = true;
                    }
                    else
                    {
                        b = false;
                    }

                    if (b == false)
                    {
                        write(clientSocket, "Error 103:", 11);
                        return;
                    }

                    char detailsFiles[524288];
                    for (int i = 0; i < 524288; i++)
                    {
                        detailsFiles[i] = 0;
                    }

                    write(clientSocket, "Downloading the file !!", 24);

                    if (read(clientSocket, detailsFiles, 524288))
                    {
                        vector<string> fd = stringCut(string(detailsFiles), '$');

                        string rep = "";

                        if (seeders[rec_input[1]].find(fd[0]) != seeders[rec_input[1]].end())
                        {
                            for (auto i : seeders[rec_input[1]][fd[0]])
                            {
                                if (isLogged[i] == 1)
                                {
                                    rep = rep + usernameToPort[i] + "$";
                                }
                            }

                            rep = rep + fileSize[fd[0]];

                            logWrite("List of seeders: " + rep);

                            write(clientSocket, &rep[0], rep.length());

                            char sample[5];
                            read(clientSocket, sample, 5);
                            write(clientSocket, &hashofPieces[fd[0]][0], hashofPieces[fd[0]].length());

                            seeders[rec_input[1]][rec_input[2]].insert(clientUserID);
                        }
                        else
                        {
                            write(clientSocket, "File not found", 15);
                        }
                    }
                }
            }
            else
            {
                write(clientSocket, "Invalid number of arguments", 28);
            }
        }
        else
        {
            write(clientSocket, "Invalid Command", 16);
        }
    }

    logWrite("-- Thread for client socket " + CS + " has ended--");
    close(clientSocket);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cout << "Give correct format of arguments" << endl;
        return -1;
    }

    logFile = string(argv[2]) + "_log.txt";
    FILE *file = fopen(logFile.c_str(), "w"); // "w" opens the file for writing (creates or truncates the file)

    if (file == NULL)
    {
        std::cerr << "Failed to create or clear the log file." << std::endl;
        exit(1);
    }

    fclose(file);

    vector<string> trackersInfo = readfile(argv[1]);

    if (string(argv[2]) != "2")
    {
        t1_ip = trackersInfo[0];
        t1_port = stoi(trackersInfo[1]);
        cur_IP_of_Tracker = trackersInfo[0];
        cur_Port_of_Tracker = stoi(trackersInfo[1]);
    }
    else if (string(argv[2]) == "2")
    {
        t2_ip = trackersInfo[2];
        t2_port = stoi(trackersInfo[3]);
        cur_IP_of_Tracker = trackersInfo[2];
        cur_Port_of_Tracker = stoi(trackersInfo[3]);
    }

    int trackerSocket;

    // Create a socket
    trackerSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (trackerSocket == -1)
    {
        perror("Error creating socket");
        return -1;
    }

    logWrite("Socket created for tracker");

    int option = 1;
    int size_option = sizeof(option);
    int op = setsockopt(trackerSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, size_option);

    if (op)
    {
        perror("setsockopt");
        return -1;
    }

    // Bind the socket to an IP address and port
    struct sockaddr_in serverAddr;

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(cur_Port_of_Tracker); // Port number

    if (inet_pton(AF_INET, &cur_IP_of_Tracker[0], &serverAddr.sin_addr) <= 0)
    {
        cout << endl
             << "Address not supported" << endl;
        return -1;
    }

    int bind_disc = bind(trackerSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    if (bind_disc == -1)
    {
        cout << "Error binding socket" << endl;
        return 1;
    }
    logWrite("Bind Complete");

    int listen_disc = listen(trackerSocket, 3);

    if (listen_disc < 0)
    {
        cout << "listen error" << endl;
        return -1;
    }

    logWrite("Listening!");
    struct sockaddr_in clientAddrSize;
    int addressLength = sizeof(clientAddrSize);

    pthread_t exitThreadId;
    if (pthread_create(&exitThreadId, NULL, exitFunction, NULL) < 0)
    {
        perror("pthread");
        return -1;
    }

    vector<thread> vectorOfThreads;

    for (;;)
    {
        int clientSocket;

        clientSocket = accept(trackerSocket, (struct sockaddr *)&serverAddr, (socklen_t *)&addressLength);

        if (clientSocket < 0)
        {
            cout << "Error in Accepting Request";
            logWrite("Accepting error");
        }
        logWrite("Accepted Connection !");

        thread t = thread(commandFunctions, clientSocket);
        vectorOfThreads.push_back(move(t));
    }

    joinThreads(vectorOfThreads);

    logWrite("The Tracker is Exiting");
    return 0;
}
