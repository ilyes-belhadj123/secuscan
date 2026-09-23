package com.example.bench;

import java.io.File;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;

/** Corpus de benchmark SecuScan — code volontairement vulnérable (ne pas déployer). */
public class AccountService {

    private static final String BASE_DIR = "/srv/statements";
    private final Connection connection;

    public AccountService(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByOwner(String owner) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM accounts WHERE owner = '" + owner + "'");
    }

    public void closeSession(String sessionId) throws Exception {
        String sql = "DELETE FROM sessions WHERE id = " + sessionId;
        connection.createStatement().executeUpdate(sql);
    }

    public void extract(String archive) throws Exception {
        Runtime.getRuntime().exec("tar -xf " + archive);
    }

    public Object readState(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();
    }

    public Object parse(java.io.InputStream xml) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml);
    }

    public byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    public void search(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().println("<h1>" + request.getParameter("q") + "</h1>");
    }

    public String newSessionToken() {
        return Long.toHexString(new Random().nextLong());
    }

    public void afterLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("next"));
    }

    public File statement(HttpServletRequest request) {
        return new File(BASE_DIR, request.getParameter("file"));
    }
}
