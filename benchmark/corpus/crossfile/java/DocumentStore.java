package com.acme.documents;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

// Benchmark : méthodes appelées avec une entrée utilisateur depuis DocumentController (vulnérable).
public class DocumentStore {
    public byte[] readDocument(String fileName) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/documents/" + fileName));
    }

    public void mirrorRemote(String address) throws IOException {
        try (InputStream in = new URL(address).openStream()) {
            in.transferTo(OutputStream.nullOutputStream());
        }
    }
}
