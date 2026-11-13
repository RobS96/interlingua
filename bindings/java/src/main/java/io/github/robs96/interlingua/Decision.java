package io.github.robs96.interlingua;

/** A router's answer for one envelope. */
public record Decision(String verdict, String nextHop, String reason, String auditLine, byte[] forward) {
}
