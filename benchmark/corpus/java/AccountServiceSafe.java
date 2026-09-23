package com.example.bench;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

/** Corpus de benchmark SecuScan — code sûr (aucune alerte attendue). */
public class AccountServiceSafe {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final Connection connection;

    public AccountServiceSafe(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByOwner(String owner) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE owner = ?");
        ps.setString(1, owner);
        return ps.executeQuery();
    }

    public void extract(java.nio.file.Path archive) throws Exception {
        new ProcessBuilder("tar", "-xf", archive.toString()).start();
    }

    public Object parse(java.io.InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder().parse(xml);
    }

    public byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public String newSessionToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return java.util.HexFormat.of().formatHex(bytes);
    }
}
