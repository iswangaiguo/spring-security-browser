package com.imooc.security.browser;

import org.apache.tomcat.jdbc.pool.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.social.security.SpringSocialConfigurer;

import com.imooc.security.core.authentication.AbstractChannelSecurityConfig;
import com.imooc.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.imooc.security.core.properties.BrowserProperities;
import com.imooc.security.core.properties.SecurityConstants;
import com.imooc.security.core.properties.SecurityProperties;
import com.imooc.security.core.validate.code.ValidateCodeSecurityConfig;

@Configuration
public class BrowserSecurityBrowser extends AbstractChannelSecurityConfig {

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	UserDetailsService userDetailsService;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Autowired
	private SpringSocialConfigurer imoocSocialSecurityConfig;
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;
	
	@Autowired
	ValidateCodeSecurityConfig validateCodeSecurityConfig;
	
	
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		//tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		applyPasswordAuthenticationConfig(http);
		
		http.apply(validateCodeSecurityConfig)
				.and()
			.apply(smsCodeAuthenticationSecurityConfig)
				.and()	
			.apply(imoocSocialSecurityConfig)
				.and()
			.rememberMe()
				.tokenRepository(persistentTokenRepository())
				.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
				.userDetailsService(userDetailsService)
				.and()
			.authorizeRequests()
				.antMatchers(
							SecurityConstants.DEFAULT_UNAUTHENTICATION_URL, 
							//SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
							securityProperties.getBrowser().getLoginPage(),
							SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*",
							securityProperties.getBrowser().getSignUpUrl(),
							"/user/regist",
							"/social/user")
							.permitAll()
				.anyRequest()
				.authenticated()
				.and()
			.csrf().disable();
			
	}
	
} 