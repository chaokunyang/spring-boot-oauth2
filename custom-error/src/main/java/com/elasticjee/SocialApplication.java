package com.elasticjee;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * @author yangck
 */
@SpringBootApplication
@EnableOAuth2Sso
@Controller
public class SocialApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @RequestMapping("/user")
    @ResponseBody
    public Principal user(Principal principal) {
        return principal;
    }

    // capture an authentication error and redirect to the home page with that flag set in query parameters
    @RequestMapping("/unauthenticated")
    public String unauthenticated() {
        return "redirect:/?error=true";
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
                .authenticated().and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    //  be used to construct the authorities (typically "roles") of an authenticated user. We can use that hook to assert the the user is in the correct orignization, and throw an exception if not
    @Bean
    public AuthoritiesExtractor authoritiesExtractor(OAuth2RestOperations template) {
        return map -> {
            String url = (String) map.get("organizations_url");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> orgs = template.getForObject(url, List.class);
            if (orgs.stream()
                    .anyMatch(org -> "spring-projects".equals(org.get("login")))) {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
            }
            throw new BadCredentialsException("Not in Spring Projects origanization"); // If there is no match, we throw BadCredentialsException and this is picked up by Spring Security and turned in to a 401 response.
        };
    }

    @Bean
    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
        return new OAuth2RestTemplate(resource, context);
    }

    // mapping from an unauthenticated response (HTTP 401, a.k.a. UNAUTHORIZED) to the "/unauthenticated"
    @Configuration
    protected static class ServletCustomizer {
        @Bean
        public EmbeddedServletContainerCustomizer customizer() {
            return container -> container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
        }
    }
}
