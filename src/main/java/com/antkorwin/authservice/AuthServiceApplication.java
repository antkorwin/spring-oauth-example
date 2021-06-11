package com.antkorwin.authservice;

import java.security.Principal;

import lombok.RequiredArgsConstructor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}
}


@Configuration
@EnableResourceServer
class ResourceServerConfig {

}

@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
class OAuthConfig extends AuthorizationServerConfigurerAdapter {

	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;

	@Bean
	public static NoOpPasswordEncoder passwordEncoder() {
		return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		super.configure(security);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
		       .withClient("my-client")
		       .secret("my-secret")
		       .authorizedGrantTypes("password", "refresh_token", "access_token")
		       .scopes("openid");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.userDetailsService(userDetailsService)
		         .allowedTokenEndpointRequestMethods(HttpMethod.POST, HttpMethod.GET)
		         .authenticationManager(authenticationManager);
	}
}

@Configuration
class AuthenticationManagerConfig extends WebSecurityConfigurerAdapter {

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}


@Service
class UserDetailServiceImpl implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if (username.equals("admin")) {
			return new User("admin",
			                "q1w2e3r4",
			                AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
		}

		if (username.equals("user")) {
			return new User("user",
			                "q1w2e3r4",
			                AuthorityUtils.createAuthorityList("ROLE_USER"));
		} else {
			throw new RuntimeException("not found this user");
		}
	}
}

@RestController
@RequestMapping("auth")
class AuthController {

	@GetMapping("user")
	public Principal getPrincipal(Principal principal) {
		return principal;
	}
}

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityMethodConfig extends GlobalMethodSecurityConfiguration {

	@Bean
	public OAuth2MethodSecurityExpressionHandler oauthExpressionHandler() {
		return new OAuth2MethodSecurityExpressionHandler();
	}
}

@RestController
@RequestMapping("/bar")
class BarController {

	@GetMapping("/beer")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminEndPoint() {
		return "Your beers: 🍺🍺🍺\n";
	}

	@GetMapping("/burger")
	@PreAuthorize("hasRole('USER') || hasRole('ADMIN')")
	public String userEndPoint() {
		return "Bon Appetite: 🍔🍔🍔\n";
	}
}

@RestController
@RequestMapping("/nuclear")
class NuclearController {

	@GetMapping("/destroy")
	@PreAuthorize("hasRole('ADMIN')")
	public String nuclearEndPoint() {
		return "     _.-^^---....,,--       \n" +
		       " _--                  --_  \n" +
		       "<                        >)\n" +
		       "|                         | \n" +
		       " \\._                   _./  \n" +
		       "    ```--. . , ; .--'''       \n" +
		       "          | |   |             \n" +
		       "       .-=||  | |=-.   \n" +
		       "       `-=#$%&%$#=-'   \n" +
		       "          | ;  :|     \n" +
		       " _____.,-#%&$@%#&#~,._____";
	}
}





