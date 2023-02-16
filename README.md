# GoogleOAuthAPI
This is simple google oauth code example for c# and asp.net

## You can use
ASP.NET WebForm, ASP.NET MVC, ASP.NET WebAPI, etc...

## Nuget requirements
Newtonsoft.Json  
BCrypt

## How to use code?
    //id = oauth id
    //secret = oauth secret
    //redirect = redirect to your webpage when user clicked google account, this will response data in url parameters
    //stateKey = any key, safely save it
    GoogleOAuth google = new GoogleOAuth("id", "secret", "redirect", "stateKey");
    
    //Get Google Login Url to Frontend
    string url = google.GetAuthUrl();
    
    //Verify state hash, avoid CSRF
    bool isSuccess = google.StateVerify(stateHash);
    
    //Get access token from code
    GoogleOAuth.TokenData token = google.GetAccessToken(code);
    
    //Get user info from access token
    GoogleOAuth.UserInfo userInfo = google.GetUserInfo(token);
    
    //Database access, etc...
