# NodeJS,Mongoose,Express Project in MVC Architecture

## MERN AUTH Backend

## About

- This is a Node application, developed using MVC pattern with Node.js, ExpressJS, and Mongoose.
- MongoDB database is used for data storage, with object modeling provided by Mongoose.

## Features

- **User Authentication**: Secure user authentication and authorization.

## Initial

1. Install all dependency
   `$ npm install`

2. Start development server
   `$ npm run dev`

### ENV

    ```
        PORT=5000
        MONGODB_URL=
        CORS_ORIGIN=*

        ACCESS_TOKEN_SECRET = mern-task-upwork
        ACCESS_TOKEN_EXPIRY = 1d

        GOOGLE_CALLBACKURL=http://localhost:5000/auth/google/callback
        GOOGLE_ERRORURL=http://localhost:5000/auth/google/error
        GOOGLE_REDIRECTURL=http://localhost:3000/
        GOOGLE_CLIENTSECRET=
        GOOGLE_CLIENTID=
        GOOGLE_API_KEY=XXXXXXX
    ```

## folder Structure

└───src
├───config  
 ├───controllers
│ └───userapp
│ └───v1/authController.js
├───db
| └───dbService.js
| └───index.js
├───middlewares
| └───auth.js
├───models
| └───user.model.js
├───routes
│ └───USERAPP/user.router.js
| └───common.js [google-auth-route]
├───services
| └───auth.service.js
└───utils
| ├───response
| └───validation
└───app.js
└───constant.js
└───index.js

## How to use generated APIs:

[Click here to visit documentation](https://documenter.getpostman.com/view/27961443/2sA3XTdKCm/ "API Documentation")
