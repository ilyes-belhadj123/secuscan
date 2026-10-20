package com.acme.reports;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// Benchmark : flux de données sur plusieurs lignes et familles de failles récentes (vulnérable).
public class ReportController extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        String sql = "SELECT * FROM reports WHERE title = '" + title + "'";
        try (Statement stmt = conn.createStatement()) {
            stmt.executeQuery(sql);
        } catch (SQLException e) {
            throw new IOException(e);
        }

        String source = request.getParameter("source");
        InputStream in = new URL(source).openStream();
        in.close();

        String name = request.getParameter("name");
        File report = new File("/srv/reports/" + name);
        response.getWriter().println("<h1>" + name + "</h1>");
    }

    byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
