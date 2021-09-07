package com.camunda.example.oauth2.config;

import com.azure.spring.aad.webapp.AADWebSecurityConfigurerAdapter;
import com.camunda.example.oauth2.filter.WebAppAuthenticationProvider;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import static java.util.Collections.singletonMap;
import static org.camunda.bpm.engine.rest.security.auth.ProcessEngineAuthenticationFilter.AUTHENTICATION_PROVIDER_PARAM;
import static org.springframework.boot.autoconfigure.security.SecurityProperties.BASIC_AUTH_ORDER;

@Configuration
@EnableWebSecurity(debug = true)
@Order(BASIC_AUTH_ORDER - 15)
public class WebAppSecurityConfig extends AADWebSecurityConfigurerAdapter {

    private final Logger logger = LoggerFactory.getLogger(WebAppSecurityConfig.class.getName());

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        super.configure(http);
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/app/admin/**", "/app/cockpit/**", "/app/tasklist/**").authenticated()
                .and()
                .authorizeRequests().antMatchers("/**").permitAll();

    }

    @Bean
    @Order(BASIC_AUTH_ORDER - 15)
    public FilterRegistrationBean<ContainerBasedAuthenticationFilter> containerBasedAuthenticationFilter() {

        logger.info("++++++++ WebAppSecurityConfig.containerBasedAuthenticationFilter()....");
        FilterRegistrationBean<ContainerBasedAuthenticationFilter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
        filterRegistration.setInitParameters(singletonMap(AUTHENTICATION_PROVIDER_PARAM, WebAppAuthenticationProvider.class.getName()));
        filterRegistration.setOrder(101); // make sure the filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/*");
        return filterRegistration;

    }

}
