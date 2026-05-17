package br.com.atesta.assinatura;

import java.util.ArrayList;
import java.util.List;

public class SignatureInfo {
    public int index;
    public String name;
    public String reason;
    public String location;
    public String contactInfo;
    public String signDate;
    public String filter;
    public String subFilter;
    public Boolean padesLikely;
    public Boolean demoiselleChecked;
    public Boolean demoiselleValid;
    public Boolean icpBrasil;

    // Assinatura gov.br/e-gov
    public Boolean govBr;
    public Boolean govBrAdvanced;
    public Boolean govBrIssuerDetected;
    public String govBrIssuerMatchedBy;
    public String govBrValidationStatus;
    public String govBrMessage;

    // Resultado técnico individual da assinatura
    public Boolean valid;
    public String validationStatus;
    public String validationMessage;
    public Boolean signatureIntegrityValid;
    public Boolean byteRangeValid;
    public Boolean finalDocumentCovered;
    public Boolean finalDocumentAcceptable;
    public Boolean certificateValidAtSigning;
    public Boolean revocationChecked;
    public String revocationMethod;
    public Boolean revoked;
    public String revocationStatus;
    public String revocationSource;
    public Boolean revocationEvidenceValid;
    public Boolean revocationFresh;
    public Boolean timestampPresent;
    public Boolean timestampValid;
    public String standard;
    public String validationLevel;

    public String certificateSubject;
    public String certificateIssuer;
    public String certificateNotBefore;
    public String certificateNotAfter;
    public String certificateSerialNumber;
    public String certificateSerialNumberHex;
    public String certificateIssuerName;

    public List<String> validatorErrors = new ArrayList<>();
    public List<String> validatorWarnings = new ArrayList<>();
}
