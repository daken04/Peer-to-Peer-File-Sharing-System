#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <pthread.h>
using namespace std;

bool logged;
string logFile, t1_ip, t2_ip, cur_IP_of_Client;
uint16_t t1_port, t2_port, cur_Port_of_Client;
unordered_map<string, unordered_map<string, bool>> isUploaded;
unordered_map<string, string> F2FPath;
unordered_map<string, vector<int>> ChunkInfo;
unordered_map<string, string> downloaded;
vector<string> curFilePiecewiseHash;
vector<vector<string>> currentDownloadinFileChunks;

struct getChunckDetails
{
    string filename;
    string serverPeerIP;
    long long int chunkNum;
    string destination;
};

struct clientFileDet
{
    string filename;
    string serverPeerIP;
    long long int filesize;
};

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

vector<string> readfile(char *path)
{
    const char *filename = path;
    vector<string> lines;

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

int connTracker(int Tnum, struct sockaddr_in &serv_addr, int sock)
{
    char *curTrackerIp;
    uint16_t curTrackerPort;

    if (Tnum == 2)
    {
        curTrackerIp = &t2_ip[0];
        curTrackerPort = t2_port;
    }
    else if (Tnum != 2)
    {
        curTrackerIp = &t1_ip[0];
        curTrackerPort = t1_port;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(curTrackerPort);
    bool b = false;

    if (inet_pton(AF_INET, curTrackerIp, &serv_addr.sin_addr) <= 0)
    {
        b = true;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        b = true;
    }

    if (b != false)
    {
        if (Tnum != 2)
        {
            return connTracker(2, serv_addr, sock);
        }
        else if (Tnum == 2)
        {
            return -1;
        }
    }
    logWrite(to_string(curTrackerPort) + " server is connected");
    return 0;
}

string getHash(char *p)
{
    FILE *fb = fopen(p, "rb");

    long long int size = 0;

    if (fb)
    {
        fseek(fb, 0, SEEK_END);
        size = ftell(fb);
        size++;
        fclose(fb);
    }
    else
    {
        cout << "File not found" << endl;
        size = -1;
    }

    long long fileSize = size;

    if (fileSize < 0)
    {
        return "$";
    }

    int segment = (fileSize / 524288) + 1;
    char line[32769];

    string hash = "";

    FILE *fp1 = fopen(p, "r");
    int accum;
    if (fp1)
    {
        for (int i = 0; i < segment; i++)
        {
            int rc;
            accum = 0;
            string segStr;

            while (accum < 524288 && (rc = fread(line, 1, min(32767, 524288 - accum), fp1)))
            {
                line[rc] = '\0';
                accum = accum + strlen(line);
                segStr = segStr + line;
                memset(line, 0, sizeof(line));
            }

            unsigned char md[20];
            if (!SHA1(reinterpret_cast<const unsigned char *>(&segStr[0]), segStr.length(), md))
            {
                printf("Error in hashing\n");
            }
            else
            {
                for (int i = 0; i < 20; i++)
                {
                    char buf[3];
                    sprintf(buf, "%02x", md[i] & 0xff);
                    hash += string(buf);
                }
            }
            hash += "$";
        }

        fclose(fp1);
    }
    else
    {
        printf("File not found.\n");
    }

    hash.pop_back();
    hash.pop_back();
    return hash;
}

// Chunks
void setChunkVec(const string &filename, long long leftIndex, long long rightIndex, bool uploaded)
{
    if (uploaded)
    {
        // Initialize a vector of 1s to indicate all chunks are uploaded.
        ChunkInfo[filename] = vector<int>(rightIndex - leftIndex + 1, 1);
        return;
    }
    else
    {
        // Mark the specific chunk at 'leftIndex' as uploaded.
        if (ChunkInfo.find(filename) != ChunkInfo.end() && leftIndex >= 0 && leftIndex < ChunkInfo[filename].size())
        {
            ChunkInfo[filename][leftIndex] = 1;
        }
    }
    // Log the update.
    logWrite("Chunk updated for " + filename + " at " + to_string(leftIndex));
}

bool writeChunk(int peersock, long long int chunkNum, const char *filepath)
{
    const int chunkSize = 524288;
    char buffer[chunkSize];
    string content;
    int totalBytesWritten = 0;

    while (totalBytesWritten < chunkSize)
    {
        int bytesRead = read(peersock, buffer, chunkSize - 1);
        if (bytesRead <= 0)
        {
            break;
        }
        buffer[bytesRead] = 0;

        FILE *file = fopen(filepath, "r+b"); // "r+b" opens the file for reading and writing (binary mode)

        if (file == nullptr)
        {
            std::cerr << "Error opening file: " << filepath << std::endl;
            return 1;
        }

        int seekResult = fseek(file, chunkNum * chunkSize + totalBytesWritten, SEEK_SET);

        if (seekResult != 0)
        {
            std::cerr << "Error seeking in the file." << std::endl;
            fclose(file);
            return 1;
        }

        size_t bytesWritten = fwrite(buffer, 1, bytesRead, file);

        if (bytesWritten != bytesRead)
        {
            std::cerr << "Error writing to the file." << std::endl;
            fclose(file);
            return 1;
        }

        fclose(file);

        logWrite("File modified successfully.");

        logWrite("Written at: " + to_string(chunkNum * chunkSize + totalBytesWritten));
        logWrite("Written till: " + to_string(chunkNum * chunkSize + totalBytesWritten + bytesRead - 1));

        content += buffer;
        totalBytesWritten += bytesRead;
        memset(buffer, 0, chunkSize);
    }

    string hash;
    unsigned char md[SHA_DIGEST_LENGTH];
    if (!SHA1(reinterpret_cast<const unsigned char *>(content.c_str()), content.length(), md))
    {
        cerr << "Error in hashing" << endl;
        return false;
    }
    else
    {
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            char buf[3];
            sprintf(buf, "%02x", md[i] & 0xff);
            hash += string(buf);
        }
    }

    // Remove trailing "$" character
    if (!hash.empty() && hash.back() == '$')
    {
        hash.pop_back();
    }

    if (hash != curFilePiecewiseHash[chunkNum])
    {
    }

    string filename = stringCut(filepath, '/').back();
    setChunkVec(filename, chunkNum, chunkNum, false);

    return true;
}

string connectToPeer(char *serverPeerIP, char *serverPortIP, string command)
{
    int peersock = 0;
    struct sockaddr_in peer_serv_addr;

    logWrite("\nInside connectToPeer");

    int temppeer = (peersock = socket(AF_INET, SOCK_STREAM, 0));

    if (temppeer < 0)
    {
        cout << "\n Socket creation error \n";
        return "error";
    }
    logWrite("Socket is Created");

    peer_serv_addr.sin_family = AF_INET;

    string st = string(serverPortIP);
    int peerPort = stoi(st);
    peer_serv_addr.sin_port = htons(peerPort);
    int tempinet_pton = inet_pton(AF_INET, serverPeerIP, &peer_serv_addr.sin_addr);
    if (tempinet_pton < 0)
    {
        perror("Connection Error");
    }
    int tempconnect = connect(peersock, (struct sockaddr *)&peer_serv_addr, sizeof(peer_serv_addr));
    if (tempconnect < 0)
    {
        perror("Connection Error");
    }
    logWrite("Connected to peer " + string(serverPeerIP) + ":" + to_string(peerPort));

    string curcmd = stringCut(command, '$').front();
    logWrite("Current command " + curcmd);

    if (curcmd == "get_chunk_vector")
    {
        if (send(peersock, &command[0], strlen(&command[0]), MSG_NOSIGNAL) == -1)
        {
            cout << "Error: " << strerror(errno) << endl;
            return "error";
        }
        logWrite("Sent command to peer: " + command);
        char server_reply[10240];
        for (int i = 0; i < 10240; i++)
        {
            server_reply[i] = 0;
        }
        int tempread = read(peersock, server_reply, 10240);
        if (tempread < 0)
        {
            perror("err: ");
            return "error";
        }
        logWrite("Got reply: " + string(server_reply));
        close(peersock);
        return string(server_reply);
    }
    else if (curcmd == "get_file_path")
    {
        if (send(peersock, &command[0], strlen(&command[0]), MSG_NOSIGNAL) == -1)
        {
            cout << "Error: " << strerror(errno) << endl;
            return "error";
        }
        char server_reply[10240] = {0};
        if (read(peersock, server_reply, 10240) < 0)
        {
            perror("err: ");
            return "error";
        }
        logWrite("Server reply for get file path: " + string(server_reply));
        F2FPath[stringCut(command, '$').back()] = string(server_reply);
    }
    else if (curcmd == "get_chunk")
    {
        int tempsend = send(peersock, &command[0], strlen(&command[0]), MSG_NOSIGNAL);
        if (tempsend == -1)
        {
            cout << "Error: " << strerror(errno) << endl;
            return "error";
        }
        logWrite("Sent command to peer: " + command);
        vector<string> cmdtokens = stringCut(command, '$');

        string despath = cmdtokens[3];
        long long int chunkNum = stoll(cmdtokens[2]);
        logWrite("\nGetting chunk " + to_string(chunkNum) + " from " + string(serverPortIP));

        writeChunk(peersock, chunkNum, &despath[0]);

        return "ss";
    }

    close(peersock);
    logWrite("Terminating connection with " + string(serverPeerIP) + ":" + to_string(peerPort));
    return "aa";
}

void getChunkInfo(clientFileDet *pf)
{

    logWrite("Getting chunk info of : " + pf->filename + " from " + pf->serverPeerIP);

    vector<string> serverPeerAddress = stringCut(string(pf->serverPeerIP), ':');

    string command = "get_chunk_vector$" + string(pf->filename);

    string response = connectToPeer(&serverPeerAddress[0][0], &serverPeerAddress[1][0], command);
    int i = 0;
    while (i < currentDownloadinFileChunks.size())
    {
        if (response[i] == '1')
        {
            currentDownloadinFileChunks[i].push_back(string(pf->serverPeerIP));
        }
        i++;
    }

    delete pf;
}

void getChunk(getChunckDetails *reqdChunk)
{

    logWrite("Chunk fetching details :" + reqdChunk->filename + " " +
             reqdChunk->serverPeerIP + " " + to_string(reqdChunk->chunkNum));

    string filename = reqdChunk->filename;
    vector<string> serverPeerIP = stringCut(reqdChunk->serverPeerIP, ':');
    long long chunkNum = reqdChunk->chunkNum;
    string destination = reqdChunk->destination;

    string command = "get_chunk$" + filename + "$" + to_string(chunkNum) + "$" + destination;
    connectToPeer(&serverPeerIP[0][0], &serverPeerIP[1][0], command);

    delete reqdChunk;
    return;
}

string getFileHash(const char *p)
{

    FILE *file = fopen(p, "r");
    if (file == nullptr)
    {
        std::cerr << "Error opening file: " << p << std::endl;
        return ""; // Return an empty string to indicate an error
    }

    std::ostringstream buf;
    char c;

    while (fread(&c, 1, 1, file) == 1)
    {
        buf.put(c);
    }

    fclose(file); // Close the file

    string contents = buf.str();
    string hash;

    unsigned char md[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char *>(contents.c_str()), contents.length(), md))
    {
        cerr << "Error in hashing" << endl;
        return ""; // Return an empty string to indicate an error
    }
    else
    {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            char buf[3];
            sprintf(buf, "%02x", md[i] & 0xff);
            hash += string(buf);
        }
        return hash;
    }
}

int downloadFile(vector<string> inpt, int sock)
{

    if (inpt.size() != 4)
    {
        return 0;
    }

    string fileDetails = "";
    fileDetails = fileDetails + inpt[2] + "$";
    fileDetails = fileDetails + inpt[3] + "$";
    fileDetails = fileDetails + inpt[1];

    logWrite("sending details for downloading the file : " + fileDetails);

    int tempSend = send(sock, &fileDetails[0], strlen(&fileDetails[0]), MSG_NOSIGNAL);
    if (tempSend == -1)
    {
        printf("Error: %s\n", strerror(errno));
        return -1;
    }

    char server_reply[524288];
    for (int i = 0; i < 524288; i++)
    {
        server_reply[i] = 0;
    }
    char dum[5];
    read(sock, server_reply, 524288);

    if (string(server_reply) == "File not found")
    {
        cout << server_reply << endl;
        return 0;
    }

    vector<string> peers = stringCut(server_reply, '$');

    strcpy(dum, "test");
    write(sock, dum, 5);

    bzero(server_reply, 524288);
    read(sock, server_reply, 524288);

    vector<string> tmp = stringCut(string(server_reply), '$');
    curFilePiecewiseHash = tmp;

    //--------

    long long int filesize = stoll(peers.back());
    peers.pop_back();
    long long int segments = filesize / 524288 + 1;
    currentDownloadinFileChunks.clear();
    currentDownloadinFileChunks.resize(segments);

    vector<thread> threads, threads2;

    int i = 0;
    while (i < peers.size())
    {
        clientFileDet *pf = new clientFileDet();
        pf->filename = inpt[2];
        pf->serverPeerIP = peers[i];
        pf->filesize = segments;
        threads.push_back(thread(getChunkInfo, pf));
        i++;
    }

    joinThreads(threads);

    logWrite("filled in default values to file");
    i = 0;
    while (i < currentDownloadinFileChunks.size())
    {
        if (currentDownloadinFileChunks[i].size() == 0)
        {
            cout << "All parts of the file are not available." << endl;
            return 0;
        }
        i++;
    }

    threads.clear();
    srand((unsigned)time(0));
    long long int segmentsReceived = 0;

    string des_path = inpt[3] + "/" + inpt[2];
    FILE *fp = fopen(&des_path[0], "r+");
    if (fp != 0)
    {
        printf("The file already exists.\n");
        fclose(fp);
        return 0;
    }
    std::string ss(filesize, '\0');
    FILE *file = fopen(des_path.c_str(), "wb"); // "wb" specifies binary mode for writing

    if (file == nullptr)
    {
        std::cerr << "Failed to create the file." << std::endl;
        exit(1);
    }

    fwrite(ss.c_str(), 1, ss.size(), file);
    fclose(file);

    ChunkInfo[inpt[2]].resize(segments, 0);

    vector<int> cil(segments, 0);
    ChunkInfo[inpt[2]] = cil;

    string peerToGetFilepath;

    while (segmentsReceived < segments)
    {
        logWrite("getting segment no: " + to_string(segmentsReceived));

        long long int randompiece;
        while (true)
        {
            randompiece = rand() % segments;
            logWrite("randompiece = " + to_string(randompiece));
            if (ChunkInfo[inpt[2]][randompiece] == 0)
                break;
        }
        long long int peersWithThisPiece = currentDownloadinFileChunks[randompiece].size();
        string randompeer = currentDownloadinFileChunks[randompiece][rand() % peersWithThisPiece];

        getChunckDetails *req = new getChunckDetails();
        req->filename = inpt[2];
        req->serverPeerIP = randompeer;
        req->chunkNum = randompiece;
        req->destination = inpt[3] + "/" + inpt[2];

        logWrite("starting thread for chunk number " + to_string(req->chunkNum));
        ChunkInfo[inpt[2]][randompiece] = 1;

        threads2.push_back(thread(getChunk, req));
        segmentsReceived++;
        peerToGetFilepath = randompeer;
    }

    joinThreads(threads2);

    cout << "Download completed" << endl;

    downloaded.insert({inpt[2], inpt[1]});

    vector<string> serverAddress = stringCut(peerToGetFilepath, ':');
    connectToPeer(&serverAddress[0][0], &serverAddress[1][0], "get_file_path$" + inpt[2]);
    return 0;
}

int client_commands(vector<string> input, int sock)
{
    char reply[10000];
    bzero(reply, 10000);
    read(sock, reply, 10000);
    cout << reply << endl;

    logWrite("Server response got is:" + string(reply));

    if (string(reply) == "Invalid number of arguments")
    {
        return 0;
    }

    if (input[0] == "logout")
    {
        logged = false;
    }
    else if (input[0] == "login")
    {
        if (string(reply) == "Login Successful")
        {
            logged = true;
            string clientAdd = cur_IP_of_Client + ":" + to_string(cur_Port_of_Client);
            write(sock, &clientAdd[0], clientAdd.length());
        }
    }
    else if (input[0] == "leave_group")
    {
        logWrite("Waiting for response for leaving the group");
        char buff[100];

        read(sock, buff, 100);

        cout << buff << endl;
    }
    else if (input[0] == "accept_request")
    {
        char buff[100];
        read(sock, buff, 100);
        cout << buff << endl;
    }
    else if (input[0] == "list_files")
    {
        char buff[1024];
        bzero(buff, 1024);

        read(sock, buff, 1024);
        vector<string> Files = stringCut(string(buff), '$');

        for (auto z : Files)
        {
            cout << z << endl;
        }
    }
    else if (input[0] == "upload_file")
    {
        if (string(reply) == "Error 1:")
        {
            cout << "Group doesn't exist" << endl;
            return 0;
        }
        else if (string(reply) == "Error 2:")
        {
            cout << "You are not a member of this group" << endl;
            return 0;
        }
        else if (string(reply) == "Error 3:")
        {
            cout << "File not found." << endl;
            return 0;
        }

        if (input.size() != 3)
        {
            return 0;
        }

        string fileDet = "";
        char *filePath = &input[1][0];

        int pos = 0;
        string address = string(filePath);
        string fileName;

        fileName = stringCut(address, '/').back();

        if (isUploaded[input[2]].find(fileName) != isUploaded[input[2]].end())
        {
            cout << "File is already Uploaded" << endl;

            if (send(sock, "error", 5, MSG_NOSIGNAL) == -1)
            {
                cout << "Error:" << strerror(errno);
                return -1;
            }
            return 0;
        }
        else
        {
            isUploaded[input[2]][fileName] = true;
            F2FPath[fileName] = string(filePath);
        }

        string hashs = getHash(filePath);

        if (hashs == "$")
        {
            return 0;
        }

        string filehash = getFileHash(filePath);
        long long size_of_file;

        FILE *fp = fopen(filePath, "rb");

        long long siz = -1;
        if (fp)
        {
            fseek(fp, 0, SEEK_END);
            siz = ftell(fp) + 1;
            fclose(fp);
        }
        else
        {
            printf("File not found.\n");
            size_of_file = -1;
        }
        size_of_file = siz;

        string filesize = to_string(size_of_file);

        fileDet += string(filePath) + "$";
        fileDet += string(cur_IP_of_Client) + ":" + to_string(cur_Port_of_Client) + "$";
        fileDet += filesize + "$";
        fileDet += filehash + "$";
        fileDet += hashs;

        logWrite("sedning file details for upload:" + fileDet);

        int t;
        t = send(sock, &fileDet[0], strlen(&fileDet[0]), MSG_NOSIGNAL);

        if (t == -1)
        {
            cout << "Error: " << strerror(errno) << endl;
            return -1;
        }

        char server_reply[10240];
        for (int i = 0; i < 10240; i++)
        {
            server_reply[i] = 0;
        }

        read(sock, server_reply, 10240);

        cout << server_reply << endl;

        logWrite("server reply: " + string(server_reply));

        // setChunkVector(filename, 0, stoll(filesize)/FILE_SEGMENT_SZ + 1, true);
        setChunkVec(fileName, 0, stoll(filesize) / 524288 + 1, true);
    }
    else if (input[0] == "download_file")
    {
        if (string(reply) == "Error 102:")
        {
            cout << "You need to be member of the group to download" << endl;
            return 0;
        }
        else if (string(reply) == "Error 101:")
        {
            cout << "Group does not exist" << endl;
            return 0;
        }
        else if (string(reply) == "Error 103:")
        {
            cout << "Directory not found" << endl;
            return 0;
        }

        if (downloaded.find(input[2]) != downloaded.end())
        {
            cout << "File is already downloaded" << endl;
            return 0;
        }

        return downloadFile(input, sock);
    }
    else if (input[0] == "show_downloads")
    {
        if (downloaded.empty())
        {
            cout << "Nothing downloaded yet" << endl;
        }
        else
        {
            for (auto z : downloaded)
            {
                cout << "[C] " << z.second << " " << z.first << endl;
            }
        }
    }
    else if (input[0] == "stop_share")
    {
        if (input[0].size() != 3)
        {
            return 0;
        }
        string ele2 = input[2];
        if (isUploaded.find(ele2) == isUploaded.end())
        {
            cout << "File not Uploaded" << endl;
        }
        else
        {
            string ele1 = input[1];
            isUploaded[ele1].erase(ele2);
        }
    }

    return 0;
}

void clientRequests(int cSock)
{
    string clientUID = "";

    char inputline[1024];
    for (int i = 0; i < 1024; i++)
    {
        inputline[i] = 0;
    }

    if (read(cSock, inputline, 1024) <= 0)
    {
        close(cSock);
        return;
    }

    logWrite(string(inputline) + " server was sent request by client\n");

    vector<string> inpt = stringCut(string(inputline), '$');
    logWrite(inpt[0]);

    string val = inpt[0];

    if (val == "get_chunk_vector")
    {
        string fname = inpt[1];
        vector<int> chunkvector = ChunkInfo[fname];

        string temp = "";
        for (auto z : chunkvector)
        {
            temp += to_string(z);
        }

        char *rply = &temp[0];

        write(cSock, rply, strlen(rply));
        logWrite("Sent the reply : " + string(rply));
    }
    else if (val == "get_chunk")
    {
        logWrite("Now sending chunck\n");
        string fname = F2FPath[inpt[1]];

        long long int chunckNum = stoll(inpt[2]);

        logWrite("sending " + to_string(chunckNum) + " to " + to_string(cur_Port_of_Client) + " from " + string(cur_IP_of_Client));

        FILE *fp1 = fopen(fname.c_str(), "rb"); // "rb" specifies binary mode for reading

        if (fp1 == NULL)
        {
            cerr << "Failed to open the binary file for reading." << endl;
            exit(1);
        }

        // Seek to the desired position
        fseek(fp1, chunckNum * 524288, SEEK_SET);

        logWrite("sending data starting at " + to_string(ftell(fp1)));

        char buff[524288];
        memset(buff, 0, sizeof(buff));
        int rc = 0;

        size_t count = fread(buff, 1, sizeof(buff), fp1);
        if (count == 0)
        {
            cerr << "Failed to read from the file." << endl;
            exit(1);
        }

        rc = send(cSock, buff, count, 0);
        if (rc == -1)
        {
            perror("[-]Error in sending file.");
            exit(1);
        }

        logWrite("sent till " + to_string(ftell(fp1)));

        fclose(fp1);

        // FILE* fp1 = fopen(fname.c_str(), "rb"); // "rb" specifies binary mode for reading

        // // Check if the file is open
        // if (fp1 == NULL) {
        //     cerr << "Failed to open the binary file for reading." << endl;
        //     exit(1);

        // }
        // fp1.seekg(chunckNum*524288, fp1.beg);

        // logWrite("sending data starting at " + to_string(fp1.tellg()));
        // char buff[524288];
        // for(int i=0;i<524288;i++)
        // {
        //     buff[i]=0;
        // }
        // int rc = 0;
        // string sent = "";

        // fp1.read(buff, sizeof(buff));
        // int count = fp1.gcount();
        // (rc = send(cSock, buff, count, 0));
        // if (rc== -1)
        // {
        //     perror("[-]Error in sending file.");
        //     exit(1);
        // }

        // logWrite("sent till "+to_string(fp1.tellg()));

        // fclose(fp1);
    }
    else if (val == "get_file_path")
    {
        string fname = F2FPath[inpt[1]];
        write(cSock, &fname[0], strlen(fname.c_str()));
    }

    close(cSock);
    return;
}
//--------------------------------------------------------------------------------------------------------
void *serverFunction(void *arg)
{
    logWrite("\nThis " + to_string(cur_Port_of_Client) + "will start running as a server");

    int sSock = socket(AF_INET, SOCK_STREAM, 0);
    if (sSock == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    logWrite("Server socket is created");
    int option = 1;
    if (setsockopt(sSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    vector<thread> thrd;
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port = htons(cur_Port_of_Client);

    int err1 = inet_pton(AF_INET, &cur_IP_of_Client[0], &add.sin_addr);
    if (err1 <= 0)
    {
        cout << endl
             << "Invalid Address" << endl;
        return NULL;
    }

    int b = bind(sSock, (struct sockaddr *)&add, sizeof(add));

    if (b < 0)
    {
        perror("binding failure");
        exit(EXIT_FAILURE);
    }

    if (listen(sSock, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    logWrite("LISTENING!!\n");

    int addrlen = sizeof(add);
    while (true)
    {
        int cSock;

        if ((cSock = accept(sSock, (struct sockaddr *)&add, (socklen_t *)&addrlen)) < 0)
        {
            perror("Acceptance error");

            logWrite("Error in accept");
        }

        logWrite("Accepted the Connection");
        thread t = thread(clientRequests, cSock);
        thrd.push_back(move(t));
    }
    joinThreads(thrd);

    close(sSock);
}
//--------------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cout << "Give corect argumnets" << endl;
        return -1;
    }

    string info = argv[1];
    string trackerInfo = argv[2];

    logFile = info + "_log.txt";
    FILE *file = fopen(logFile.c_str(), "w"); // "w" opens the file for writing (creates or truncates the file)

    if (file == NULL)
    {
        std::cerr << "Failed to create or clear the log file." << std::endl;
        exit(1);
    }

    fclose(file);

    int size = info.size();
    for (int i = 0; i < size; i++)
    {
        if (info[i] == ':')
        {
            cur_IP_of_Client = info.substr(0, i);
            cur_Port_of_Client = stoi(info.substr(i + 1));
        }
    }

    char curDir[128];
    getcwd(curDir, 128);
    string path = string(curDir);
    path = path + "/";
    path = path + trackerInfo;

    vector<string> trackerInform = readfile(&path[0]);

    t1_ip = trackerInform[0];
    t1_port = stoi(trackerInform[1]);
    t2_ip = trackerInform[2];
    t2_port = stoi(trackerInform[3]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        cout << "Unable to create socket" << endl;
        return -1;
    }
    logWrite("Created client socket");

    // thread to make client run as server
    pthread_t sThread;
    int j = pthread_create(&sThread, NULL, serverFunction, NULL);

    if (j == -1)
    {
        perror("pthread");
        return -1;
    }

    // connect to tracker
    struct sockaddr_in serv_addr;
    int connectT = connTracker(1, serv_addr, sock);

    if (connectT == -1)
    {
        exit(-1);
    }

    for (;;)
    {
        cout << "HERE>";
        string inpt, s;
        getline(cin, inpt);

        if (inpt.length() < 1)
        {
            continue;
        }

        stringstream ss(inpt);
        vector<string> input;

        while (ss >> s)
        {
            input.push_back(s);
        }

        // Edge cases
        if (logged != false && input[0] == "login")
        {
            cout << "Client has a Session Active currently" << endl;
            continue;
        }
        else if (input[0] != "create_user" && logged == false && input[0] != "login")
        {
            cout << "Login or Create an Account" << endl;
            continue;
        }

        if (send(sock, &inpt[0], strlen(&inpt[0]), MSG_NOSIGNAL) == -1)
        {
            printf("Error: %s\n", strerror(errno));
            return -1;
        }
        logWrite("sent to server: " + input[0]);

        client_commands(input, sock);
    }
    close(sock);
    return 0;
}