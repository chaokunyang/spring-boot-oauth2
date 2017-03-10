simple: a very basic static app with just a home page and unconditional login through via Spring Boot’s @EnableOAuth2Sso (if you visit the home page you will be automatically redirected to Facebook).
click: adds an explicit link that the user has to click to login.
logout: adds a logout link as well for authenticated users.
manual: shows how the @EnableOAuth2Sso works by unpicking it and configuring all its pieces manually.
github: adds a second login provider in Github, so the user can choose on the home page which one to use.
auth-server: turns the app into a fully-fledged OAuth2 Authorization Server, able to issue its own tokens, but still using the external OAuth2 providers for authentication.
custom-error: adds an error message for unauthenticated users, and a custom authentication based on Github API.
