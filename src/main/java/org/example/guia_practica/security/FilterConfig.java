package org.example.guia_practica.security;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
@Configuration

public class FilterConfig {
    @Bean
    public FilterRegistrationBean<UrlFilter> urlFilterRegistration()
    {
        FilterRegistrationBean<UrlFilter> registrationBean = new
                FilterRegistrationBean<>();
        registrationBean.setFilter(new UrlFilter());
        registrationBean.addUrlPatterns("/api/crypto/*");
        registrationBean.setOrder(1); // Prioridad en la cadena de filtros
        return registrationBean;
    }
}
