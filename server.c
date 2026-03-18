#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
/* To be written. This file needs to be sumitted to canvas */
typedef struct Query Query;
typedef struct Rule Rule;

struct Query{
    char Ip[17];
    char Port[6];
};
struct Rule{
    char Ip[17];
    char Ip2[17]; // if the rule has a 2 IP addresses, store the second IP address here
    char Port[6]; 
    char Port2[6]; // if the rule has a range of ports, store the second port number here
    int no; // number of ips and ports
    struct Query query[10]; // store the query that matches the rule 
    int no_of_queries;
};

char* response; // expected responce from firewall
struct Rule rules[50]; // array to store rule 
int ruleIndex; // index to keep track of the number of rules
FILE *fp; // file pointer 

extern char *processRequest (char *);
//request R
void receivedRequests();
void addRequest(char *request);
//request A
Rule parseInput(char* input);
bool checkValidRule(Rule r);
void addRule(Rule r);
bool checkValidSingleIP(char* IPAddress);
bool checkSingleValidPort(char* p);
bool checkValidIp(char *ip1, char* ip2);
bool checkValidPort(char *port1, char* port2);
unsigned long long stringToInt(char* str);
//request C
Query parseQuery(char *q);
bool checkQueryInput(Query q);
bool queryCheck(Query q);
bool compare(char* one, char* two);
//request D
void deleteRule(Rule r, int index);
int ruleExists(Rule r);
//request L
char* ruleToString(Rule r);
char* queryToString(Query q);
void display();
//freeing memory 
void deleteFileContents();

char *processRequest (char *request) {
    pthread_mutex_lock(&lock);
    response = calloc(1000,1);
    addRequest(request);
    switch (request[0])
    {
    case 'R':
        receivedRequests();
        pthread_mutex_unlock(&lock);
        return response;
    case 'A':
        Rule r1 = parseInput(request + 2);
        if (checkValidRule(r1)) { // check valid is correct and passes client test
            addRule(r1);
            sprintf(response,"Rule added");
            pthread_mutex_unlock(&lock);
            return response;
        }else {
            sprintf(response,"Invalid rule");
            pthread_mutex_unlock(&lock);
            return response;
        }
    case 'C':
        Query q = parseQuery(request + 2);
        if(checkQueryInput(q)) {
            if (queryCheck(q)){
                sprintf(response,"Connection accepted");
                pthread_mutex_unlock(&lock);
                return response;
            }
            else{
                sprintf(response,"Connection rejected");
                pthread_mutex_unlock(&lock);
                return response;
            }
        }else{
            sprintf(response,"Illegal IP address or port specified");
            pthread_mutex_unlock(&lock);
            return response;
        }
    case 'D':
        Rule r2 = parseInput(request + 2);
        if(checkValidRule(r2)){
            int index = ruleExists(r2);
            if (index>=0){ // check rule is in array 
                deleteRule(r2,index);
                sprintf(response,"Rule deleted");
                pthread_mutex_unlock(&lock);
                return response;
            }else {
                sprintf(response,"Rule not found");
                pthread_mutex_unlock(&lock);
                return response;
            }
        }
        sprintf(response,"Invalid rule");
        pthread_mutex_unlock(&lock);
        return response;
    case 'L':
        display();
        pthread_mutex_unlock(&lock);
        return response;
    case 'F':
        deleteFileContents();
        memset(rules,0,sizeof(rules));
        memset(&ruleIndex,0,sizeof(int));
        sprintf(response,"All rules deleted");
        pthread_mutex_unlock(&lock);
        return response;
    default:
        sprintf(response,"Illegal request");
        pthread_mutex_unlock(&lock);
        return response;
    }
}

/* Function to print all received requests */
void receivedRequests(){  //change to return a char* 
    fp = fopen("requests.txt", "r"); // open the file in read mode or create it if it doesn't exist
    char line[46]; // buffer to store each line of the file 46 characters is the max length of a request (rule + /0)
    while (fgets(line, sizeof(line), fp)) { // read each line of the file
        strcat(response, &line[0]); // store the line in the response variable
        //strncat(destination pointer, source pointer,size_t) concats n characters from source to destination
        //sizeof gives type size_t
    }
    fclose(fp); // close the file
}
void addRequest(char *request){
    fp = fopen("requests.txt", "a"); // open the file in append mode
    fputs(request, fp);// writes string from character pointer to file
    fprintf(fp, "\n"); //adds a new line after request 
    fclose(fp); // close the file
}
void deleteFileContents(){
    fp = fopen("requests.txt", "w");
    fclose(fp);
}

/* Functions to process rules and check for validity */
void addRule(Rule r){
    rules[ruleIndex] = r;
    ruleIndex++;
}
Rule parseInput(char *input){
    char* input_copy = calloc(strlen(input)+1, 1);
    strcpy(input_copy, input); //avoid literal strings/ read-only memory
    Rule r;
    char* token = strtok(input_copy, " "); // split the input by the space 
    r.Ip[0] = '\0'; // initialize the Ip field to an empty string
    r.Ip2[0] = '\0'; // initialize the Ip2 field to an empty string
    r.Port[0] = '\0'; // initialize the Port field to 0
    r.Port2[0] = '\0'; // initialize the Port2 field to 0
    r.no = 0;
    if(token != NULL) {
        // the first token is the IPs
        char* dash = strchr(token,'-');// if there are 2 ips splits them
        if(dash != NULL){
            size_t Ip1 = dash - token;
            strncpy(r.Ip,token, Ip1); //copies up to the dash
            r.Ip[Ip1] = '\0';// null terminator to signify end of IP1
            strcpy(r.Ip2,(dash+1));
            
        }
        else{strcpy(r.Ip,token);
        }
    }
    token = strtok(NULL, " ");
    if(token != NULL){
        char* dash = strchr(token, '-');
        if(dash != NULL){
            size_t port1 = dash - token;
            strncpy(r.Port,token, port1); //copies up to the dash
            r.Port[port1] = '\0';// null terminator to signify end of IP1
            strcpy(r.Port2,(dash +1));
            r.no = 2;
        }
        else{strcpy(r.Port,token); r.no =1;}   
    } 
    free(input_copy);
    r.no_of_queries =0;
    return r;
}
bool checkValidRule(Rule r){
    if(r.Ip[0] == '\0' || r.Port[0] == '\0'){
        return false;
    }
    else if(r.Ip2[0]== '\0' && r.Port2[0] == '\0'){
        if (checkValidSingleIP(r.Ip) && checkSingleValidPort(r.Port)){
            return true;
        } // if the rule has Ips and ports check if both are valid otherwise, rule is not valid
    }
    if(checkValidIp(r.Ip, r.Ip2) && checkValidPort(r.Port, r.Port2)){
        return true;
    }
    return false;
}
bool checkValidSingleIP(char* IPAddress){
    // check if the single IP address is valid and return true or false
    char IpCopy[17] = {0};
    strcpy(IpCopy,IPAddress);
    char *token = strtok(IpCopy, "."); // split the IP address by the dot
    int num;
    int parts = 0; 
    while (token != NULL) {
        num = atoi(token); // convert the token to an integer
        parts ++; // checks that the IP input has 4 parts 
        if (num < 0 || num > 255) { // check if the number is within valid range
            return false;
        }   
        token = strtok(NULL, "."); // get the next token
    }
    return true && (parts ==4); 
}
bool checkSingleValidPort(char* p){
    // check if the port is valid and return true or false
    int num = atoi(p); // convert string to integer
    if (num < 0 || num > 65535) {
        return false;
    }
    return true; 
}
bool checkValidIp(char *ip1, char *ip2){ // only used when there are 2 IPs 
    bool valid = true;
    // split the IP addresses and return an array of IPAddress structs
    valid = stringToInt(ip1) < stringToInt(ip2); // check if the first IP address is less than the second IP address
    return checkValidSingleIP(ip1)&& checkValidSingleIP(ip2) && valid; 
}
bool checkValidPort(char *port1, char* port2){ // only used if there are 2 ports
    bool valid = atoi(port1) < atoi(port2); // check if the first port is less than the second port
    return checkSingleValidPort(port1) && checkSingleValidPort(port2) && valid;
}
unsigned long long stringToInt(char* str){ //convert IP address to single integer
    // convert a string to an integer and return the integer
    char* strCopy = calloc(100,1);// space for 100 bytes where each character is 1 byte
    strcpy(strCopy,str); // copy so changes aren't being made to acc val;
    char* IpAsString = calloc(100,1); // allocate memory for the concatenated string
    char *token = strtok(strCopy, "."); // split the string by the dot
    while(token != NULL){
        strcat(IpAsString, token);  // Add the digits
        token = strtok(NULL, ".");   // Get next part
    }
    unsigned long long r = strtoull(IpAsString,NULL,10);
    free(strCopy);
    free(IpAsString);
    return r; // convert the concatenated string to an integer
}

/*Functions to check IP addresses and ports against a rule */
bool checkQueryInput(Query q){ // Checks query is valid Ip address and port
    if (q.Ip[0] == '\0' || q.Port[0] == '\0'){
        return false;
    }
    return checkValidSingleIP(q.Ip) && checkSingleValidPort(q.Port);
}
Query parseQuery(char *q){
    Query query; 
    query.Ip[0] = '\0';
    query.Port[0] = '\0';
    char* qcopy = calloc(strlen(q)+10,1); 
    strcpy(qcopy,q);
    char* space = strtok(qcopy," ");
    if(space != NULL){
        strcpy(query.Ip,space);
        space = strtok(NULL," ");
        if(space != NULL){
            strcpy(query.Port,space); 
            free(qcopy);
            return query;
        }
    }
    free(qcopy);
    return query;
}
bool queryCheck(Query new){ //if valid adds to rule index 
    int i;
    for(i= 0;i<ruleIndex; i++){
        if(rules[i].no == 1){ // only 1 IP and port to check 
            if(compare(new.Ip, rules[i].Ip) && compare(new.Port, rules[i].Port)){ 
                rules[i].query[rules[i].no_of_queries] = new; //add query to list 
                rules[i].no_of_queries++;//increment
                return true;
            }
        }
        else if(rules[i].no == 2){
            //check if it in range
            long long unsigned ipNO = stringToInt(new.Ip);
            long long unsigned PortNo = stringToInt(new.Port);
            
            if((ipNO >= stringToInt(rules[i].Ip) && ipNO<= stringToInt(rules[i].Ip2)) && (PortNo >= stringToInt(rules[i].Port) && PortNo <= stringToInt(rules[i].Port2))){
                rules[i].query[rules[i].no_of_queries] = new;
                rules[i].no_of_queries++;//increment
                return true;
            }
        }
    }
    return false;
}
bool compare(char* one, char* two){
    if(strlen(one) != strlen(two)){
        return false;
    }
    else{
        int i;
        for (i= 0; i<strlen(one); i++){
            if (!(one[i] == two[i])){
                return false;
            }
        }
        return true;
    }
}

/*Functions to delete a rule*/
int ruleExists(Rule r){// returns the index of the rule in the rule array 
    for (int i = 0; i < ruleIndex; i++){
        //check how many Ip pairs there are 
        if(r.no == 1 && rules[i].no == 1){
            if(compare(r.Ip, rules[i].Ip) && compare(r.Port, rules[i].Port)){ 
                return i; 
            }
        }
        else if (r.no == 2 && rules[i].no == 2){
            if ((compare(r.Ip,rules[i].Ip) && compare(r.Port,rules[i].Port))&&(compare(r.Ip2,rules[i].Ip2) && compare(r.Port2,rules[i].Port2))){
                return i;
            }
        }
    }
    return -1;
}
void deleteRule(Rule r,int index){
    // delete the rule from the receivedRequests array
    for (int j = index; j<ruleIndex; j++){
        rules[j] = rules[j+1];
    }
    ruleIndex--;
    // read up until the ruleIndex 
}

/*Functions to display rules and queries*/
char* ruleToString(Rule r){
    int i;
    int j = r.no_of_queries * 50;
    char* rule = calloc(j+75,1);
    if (r.no == 1){
        sprintf(rule,"Rule: %s  %s\n",r.Ip, r.Port);
        for(i = 0; i< r.no_of_queries; i++){
            char* q= queryToString(r.query[i]);
            rule = strcat(rule,q);
            free(q);
        }
    }
    else{
        sprintf(rule,"%s-%s %s-%s\n",r.Ip,r.Ip2, r.Port,r.Port2);
        for(i = 0; i< r.no_of_queries; i++){
            char* q = queryToString(r.query[i]);
            rule = strcat(rule,q);
            free(q);
        }
    }
    return rule; 
}
char* queryToString(Query q){
    char* query = calloc(100,1);
    sprintf(query,"Query: %s  %s\n",q.Ip, q.Port);
    return query; 
}
void display(){
    int i;
    for(i = 0; i<ruleIndex;i++){
        char* r = ruleToString(rules[i]);
        response = strcat(response, r);
        free(r);
    }
}
//for freeing memory return string literals to be copied into response so response can be freed


