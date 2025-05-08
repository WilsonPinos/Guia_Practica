package org.example.guia_practica.security;
import jakarta.servlet.http.*;
import jakarta.servlet.*;
import java.io.IOException;
import java.util.Set;

public class UrlFilter implements Filter {
    private final Set<String> allowedIps = Set.of("127.0.0.1",
            "0:0:0:0:0:0:0:1"); // IPv6 loopback también
    public void init(FilterConfig filterConfig) {}
    @Override
    public void doFilter(ServletRequest request, ServletResponse
            response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String path = req.getRequestURI();
        String clientIp = req.getRemoteAddr();
        // Log opcional (puede activarse en modo debug)
        System.out.println("Solicitud entrante: " + path + " desde IP: " + clientIp);
        if (path.startsWith("/api/crypto") &&
                !allowedIps.contains(clientIp)) {
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "Acceso denegado desde IP: " + clientIp);
            return;
        }
        chain.doFilter(request, response);
    }
    @Override
    public void destroy() {}
}