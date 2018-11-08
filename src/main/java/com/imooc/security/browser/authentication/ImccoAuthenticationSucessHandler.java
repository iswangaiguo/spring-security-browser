package com.imooc.security.browser.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.imooc.security.core.properties.LoginType;
import com.imooc.security.core.properties.SecurityProperties;

@Component("imccoAuthenticationSucessHandler")
public class ImccoAuthenticationSucessHandler extends SavedRequestAwareAuthenticationSuccessHandler{
	
	private static final Logger log = LoggerFactory.getLogger(ImccoAuthenticationSucessHandler.class);
	
	@Autowired
	private SecurityProperties securityProperties;
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		log.info("登陆成功");
		if (LoginType.JSON.equals(securityProperties.getBrowser().getLoginType())) {
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(new ObjectMapper().writeValueAsString(authentication));
		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}
	}
}

