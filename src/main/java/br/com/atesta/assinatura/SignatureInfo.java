package br.com.atesta.assinatura;

public record SignatureInfo(
        int index,
        String name,
        String reason,
        String location,
        String contactInfo,
        String signDate,
        String filter,
        String subFilter,
        boolean padesLikely
) {}
