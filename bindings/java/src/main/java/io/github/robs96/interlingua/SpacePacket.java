package io.github.robs96.interlingua;

/**
 * A CCSDS 133.0-B-2 Space Packet. {@code sequenceFlags}: 0 continuation, 1 first,
 * 2 last, 3 unsegmented. {@code consumed} is the decoded packet's length (0 when
 * building one to encode).
 */
public record SpacePacket(boolean telecommand, boolean secondaryHeader, int apid, int sequenceFlags,
        int sequenceCount, byte[] data, int consumed) {
}
