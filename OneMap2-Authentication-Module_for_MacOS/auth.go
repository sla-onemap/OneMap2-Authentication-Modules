/*****************
Created and Distributed
by One Map 2.0 Team

App has been cross-complied
to most of the OS types

Copyrighted to Singapore 
Land Authority
*****************/
package main

import (
    "os"
    "fmt"
    "io/ioutil"
    "path/filepath"
    "encoding/json"
    "strings"
    "net/http"
    "time"
    "strconv"
)

//Struct for your Access Token
type Token struct {
    AccessToken string `json:"access_token"`
    ExpiryTimestamp string `json:"expiry_timestamp"`
}

type ErrorMsg struct {
    Error string `json:"error"`
}

//Struct for your Credential
type Credential struct {
    Email string `json:"email"`
    Password string `json:"password"`
}

//Access Token Generator for One Map 2.0 API User(s)
func main(){
    //Check text file for existing token & expiry timestamp
    token := checkandgenauth()
    fmt.Println(token)
}

//Check current auth's validity & generate token
func checkandgenauth() string {
    //Getting path of auth store file
    absolutePath, _ := filepath.Abs("../authentication_module/authstore.txt")

    //Read path for token
    existingToken, err := ioutil.ReadFile(absolutePath)
    check(err)

    textFileStr := string(existingToken)

    //Different Scenarios
    if textFileStr == "" {

        //Generate token and returns
        accessjsonstr := generateToken() 
        return accessjsonstr;

    }else{

        //Split String
        s := strings.Split(textFileStr, ",")
        if len(s)>2 || len(s)<2 {
            //If auth store doesn't contain a valid string
            accessjsonstr := generateToken() 
            return accessjsonstr;
        }else{

            existingTokenStr, timestampStr := s[0], s[1]

            i, err := strconv.ParseInt(timestampStr, 10, 64)
            if err != nil {
                //If auth store contains invalid timestamp
                accessjsonstr := generateToken() 
                return accessjsonstr;
            }

            tm := time.Unix(i, 0)

            currentTime := time.Now()

            if currentTime.After(tm) {
                //If current time esclipsed existing timestamp
                accessjsonstr := generateToken() 
                return accessjsonstr;
            }else{
                //Returns existing token.
                return existingTokenStr;
            }
        }

    }

}

//Function to generate token
func generateToken() string {

    //Getting path of creds file
    CredsabsolutePath, _ := filepath.Abs("../authentication_module/credentials.txt")

    //Read path for token
    credentials, err := ioutil.ReadFile(CredsabsolutePath)
    check(err)

    credsStr := string(credentials)

    var credObj Credential;

    json.Unmarshal([]byte(credsStr), &credObj)

    //Service Endpoint for One Map 2.0
    URL := "https://developers.onemap.sg/privateapi/auth/post/getToken"

    payload := strings.NewReader("-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\n"+credObj.Email+"\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"+credObj.Password+"\r\n-----011000010111000001101001--")
    
    req, err := http.NewRequest("POST", URL, payload)
    check(err)

    req.Header.Add("content-type", "multipart/form-data; boundary=---011000010111000001101001")
    req.Header.Add("cache-control", "no-cache")

    resp, err := http.DefaultClient.Do(req)
    check(err)

    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)

    var tokenStr Token;
    var errorStr ErrorMsg;

    //Try to unmarshal error first
    json.Unmarshal([]byte(string(body)), &errorStr)

    if errorStr.Error != "" {
        return errorStr.Error;
    }

    //Unmarshal the json String into Struct
    json.Unmarshal([]byte(string(body)), &tokenStr)

    writeCredsStr := tokenStr.AccessToken + "," + tokenStr.ExpiryTimestamp

    //Getting path of auth store file
    absolutePath, _ := filepath.Abs("../authentication_module/authstore.txt")

    err = ioutil.WriteFile(absolutePath, []byte(writeCredsStr), 0644)
    check(err)

    return tokenStr.AccessToken
}

//Deflect error and os exit
func check(e error) {
    if e != nil {
        os.Exit(0)
    }
}