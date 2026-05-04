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
    public String certificateSubject;
    public String certificateIssuer;
    public String certificateNotBefore;
    public String certificateNotAfter;
    public List<String> validatorErrors = new ArrayList<>();
    public List<String> validatorWarnings = new ArrayList<>();
}
