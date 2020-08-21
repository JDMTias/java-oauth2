package com.lambdaschool.usermodel.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * This class enables and configures the Authorization Server. The class is also responsible for granting authorization to the client.
 * This class is responsible for generating and maintaining the access tokens.
 */
// 5 This is a config file so we add Configuration annotation
@Configuration
// 6 We need to tell Spring that this is where we are putting the authorization file
@EnableAuthorizationServer
// 7 Reload Pom File
// 8 Extend SuthorizationServerConfigurereAdapter.
public class AuthorizationServerConfig
        extends AuthorizationServerConfigurerAdapter
{
    /**
     * Client Id is the user name for the client application. It is read from the environment variable OAUTHCLIENTID
     */
//    9 add a client id, at first this is = lambdaid this is the username of the front end
//    client, later on we will not have it hard coded.
    static final String CLIENT_ID = System.getenv("OAUTHCLIENTID");

    /**
     * Client secret is the password for the client application. It is read from the environment variable OAUTHCLIENTSECRET
//     */
//    10. add client password, this is the password for our client, we can call it whatever we want
//    hence the secret.
    static final String CLIENT_SECRET = System.getenv("OAUTHCLIENTSECRET"); // read from environment variable

    /**
     * We are using username and password to authenticate a user
     */
//    11 grant type- when a user/client wants to get authenticated/authorized they need to send
//    us a password
    static final String GRANT_TYPE_PASSWORD = "password";

    /**
     * We are using the client id and client security combination to authorize the client.
     * The client id and security can be base64 encoded into a single API key or code
     */
//    12 or they could also send us an authrization code.
    static final String AUTHORIZATION_CODE = "authorization_code";

    /**
     * Scopes are meant to limit what a user can do with the application as a whole.
     * Here we allow the user to read from the application.
     * Currently we are not implementing scope in our applications. We are just setting up the framework to do so.
     */
//    13. with oauth2 they get a assigned a role that tell them what they are allowed to do, like
//    an admin vs a subscriber, we want further define acces so we use scope.
    static final String SCOPE_READ = "read";

    /**
     * Scopes are meant to limit what a user can do with the application as a whole.
     * Here we allow the user to write to the application.
     * Currently we are not implementing scope in our applications. We are just setting up the framework to do so.
     */
//    14. add write scope
    static final String SCOPE_WRITE = "write";

    /**
     * Scopes are meant to limit what a user can do with the application as a whole.
     * Here we say the user is trusted.
     * Currently we are not implementing scope in our applications. We are just setting up the framework to do so.
     */
//    15 add Trust
    static final String TRUST = "trust";

    /**
     * Tells how long in seconds the access code should be kept valid. After this timeout, the user has to sign on again.
     * set to -1 if you want the token to be valid forever. 1 * 60 * 60 would give us 1 hour.
     */
//    16 when you create an authenication token, that token says that user has access
////    to our app as well as who they are and what kind of acces they have, that token can be
// given a timeframe on how long it stays valid(in seconds), if we want the valid to be forever
// (as long as the user is logged in)  you add -1
    static final int ACCESS_TOKEN_VALIDITY_SECONDS = -1;

    /**
     * The token store is configured in Security Config. However, the authorization server manages it
     */
//17. we want to tell SPring where we are storing as well as where we are getting the Token from
// so we are going to create TokenStore, later, but our Authorization Server needs to know about
// it so we autowire in TokenStore.
    @Autowired
    private TokenStore tokenStore;

    /**
     * The authentication server authenticates a user to that user user gets assigned an access token that is managed by the authorization server
     */
//    18. we also need to tell spring that we have an authorization server handling all this
//    security so we will do that in AuthenticationManager but again we will add this later.
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * The authorization server must encrypt the client secret so needs to know what password encoder is in use.
     */
//  19.  The AuthServer needs to encrypt the password so SPring needs to know what encoder we are
//    going to be using which we will make in Password Encoder, again we will work on this later.
    @Autowired
    private PasswordEncoder encoder;

    /**
     * Method to configure the Client Details Service for our application. This is created and managed by Spring.
     * We just need to give it our custom configuration.
     *
     * @param configurer The ClientDetailsServiceConfigurer used in our application. Spring Boot Security created this for us.
     *                   We just use it.
     * @throws Exception if the configuration fails
     */
//    20. we need to do an override method, generate, and add configure with
//    ClientDetailServiceConfig from the options.
//    21. the generated return will be super.configure(clients), we need to erase that,  we want
//    to take
    @Override
    public void configure(ClientDetailsServiceConfigurer configurer)
            throws
            Exception
    {
//        22  we want to take clients that we are going to be configuring and we want to do it in
//        memory, everything we do in security will be saved in memory, its fast and very
//        secured, its harder to acces a system memory then disk, also if we ever need to kick
//        everyone out of out system, we can just shut it down, when that happens the
//        authorization token that is in their system will get erased and they can't get back in,
//        if we had saved it in the disk then that token does not get erased
//
//        this actually starts off as clients.inMemory,
        configurer.inMemory()
                .withClient(CLIENT_ID)
                .secret(encoder.encode(CLIENT_SECRET))
                .authorizedGrantTypes(GRANT_TYPE_PASSWORD,
                        AUTHORIZATION_CODE)
                .scopes(SCOPE_READ,
                        SCOPE_WRITE,
                        TRUST)
                .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS);
    }

    /**
     * Connects are endpoints to our custom authentication server and token store.
     * We can also rename the endpoints for certain oauth functions
     *
     * @param endpoints The Authorization Server Endpoints Configurer is created and managed by Spring Boot Security.
     *                  We give the configurer some custom configuration and let it work!
     * @throws Exception if the configuration fails
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws
            Exception
    {
        endpoints.tokenStore(tokenStore)
                .authenticationManager(authenticationManager);
        // here instead of our clients requesting authentication at the endpoint /oauth/token, they request it at the endpoint /login
        endpoints.pathMapping("/oauth/token",
                "/login");
    }
}