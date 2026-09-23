package com.acme.billing;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;

/** Acme Shop — service de facturation (démonstration volontairement vulnérable). */
public class InvoiceService {

    private static final Logger LOG = LogManager.getLogger(InvoiceService.class);
    private final Connection connection;

    public InvoiceService(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findInvoices(String customerId) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM invoices WHERE customer_id = '" + customerId + "'");
    }

    public void archive(String invoiceId) throws Exception {
        Runtime.getRuntime().exec("sh /opt/acme/archive.sh " + invoiceId);
    }

    public Object importLegacy(InputStream data) throws Exception {
        ObjectInputStream in = new ObjectInputStream(data);
        return in.readObject();
    }

    public Document parseInvoiceXml(InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xml);
    }

    public String checksum(byte[] pdf) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new java.math.BigInteger(1, md.digest(pdf)).toString(16);
    }

    public String newPaymentReference() {
        Random random = new Random();
        return "PAY-" + random.nextInt(1_000_000);
    }

    public void logAccess(String userAgent) {
        LOG.info("Accès facturation depuis : " + userAgent);
    }
}
