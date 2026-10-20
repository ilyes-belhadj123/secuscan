package com.acme.documents;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

// Benchmark : méthodes appelées uniquement avec des nombres depuis InvoiceController (aucune alerte attendue).
public class InvoiceStore {
    public byte[] readInvoice(long invoiceId) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/invoices/" + invoiceId + ".pdf"));
    }

    public void mirrorProduct(long productId) throws IOException {
        try (InputStream in = new URL("https://catalog.example.com/items/" + productId).openStream()) {
            in.transferTo(OutputStream.nullOutputStream());
        }
    }
}
