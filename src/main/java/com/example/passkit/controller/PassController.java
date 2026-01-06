package com.example.passkit.controller;

import com.example.passkit.service.PassGeneratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/pass")
@CrossOrigin(origins = "*")
public class PassController {

    private static final Logger logger = LoggerFactory.getLogger(PassController.class);

    @Autowired
    private PassGeneratorService passGeneratorService;

    @GetMapping("/generate")
    public ResponseEntity<?> generatePass() {
        try {
            byte[] pkpassData = passGeneratorService.generatePass();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(pkpassData.length);

            return new ResponseEntity<>(pkpassData, headers, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error generating pass", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to generate pass: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("PassKit Backend is running");
    }
}
