package com.acme.reports;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FilenameUtils;
import org.owasp.encoder.Encode;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// Benchmark : mêmes fonctionnalités que ReportController.java, écrites de façon sûre (aucune alerte attendue).
public class ReportControllerSafe extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        try (PreparedStatement stmt = conn.prepareStatement("SELECT * FROM reports WHERE title = ?")) {
            stmt.setString(1, title);
            stmt.executeQuery();
        } catch (SQLException e) {
            throw new IOException(e);
        }

        String source = request.getParameter("source");
        InputStream in = new URL("https://reports.example.com/feeds/"
                + URLEncoder.encode(source, StandardCharsets.UTF_8)).openStream();
        in.close();

        String name = request.getParameter("name");
        File report = new File("/srv/reports/", FilenameUtils.getName(name));
        response.getWriter().println("<h1>" + Encode.forHtml(name) + "</h1>");
    }

    byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    void configure(HttpSecurity http) throws Exception {
        http.csrf(Customizer.withDefaults());
    }
}
