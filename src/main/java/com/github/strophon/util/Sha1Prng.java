package com.github.strophon.util;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

public class Sha1Prng extends Random {
    private static final long serialVersionUID = 3581829991155417889L;
    private transient MessageDigest digest;
    private byte[] state;
    private byte[] remainder;
    private int remCount;

    public Sha1Prng() {
        this.init(null);
    }

    public Sha1Prng(byte[] seed) {
        this.init(seed);
    }

    private void init(byte[] seed) {
        getDigest();

        if(seed != null) {
            this.setSeed(seed);
        }
    }

    private void getDigest() {
        try {
            this.digest = MessageDigest.getInstance("SHA", "SUN");
        } catch(NoSuchAlgorithmException | NoSuchProviderException e) {
            try {
                this.digest = MessageDigest.getInstance("SHA");
            } catch(NoSuchAlgorithmException ex) {
                throw new InternalError("internal error: SHA-1 not available.", ex);
            }
        }
    }

    public synchronized void setSeed(byte[] seed) {
        if(this.state != null) {
            this.digest.update(this.state);

            for(int i = 0; i < this.state.length; ++i) {
                this.state[i] = 0;
            }
        }

        this.state = this.digest.digest(seed);
    }

    private static void updateState(byte[] state, byte[] digestBytes) {
        int offset = 1;
        boolean stateChanged = false;

        for(int i = 0; i < state.length; ++i) {
            int sum = state[i] + digestBytes[i] + offset;
            byte updatedByte = (byte) sum;
            stateChanged |= state[i] != updatedByte;
            state[i] = updatedByte;
            offset = sum >> 8;
        }

        if(!stateChanged) {
            ++state[0];
        }
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        getDigest();
    }

    public synchronized void nextBytes(byte[] bytes) {
        int generated = 0;
        byte[] currentBytes = this.remainder;
        if(this.state == null) {
            throw new RuntimeException("Sha1Prng not initialized.");
        }

        int startByte = this.remCount;
        int bytesToGen;
        int i;
        if(startByte > 0) {
            bytesToGen =
                    bytes.length - generated < 20 - startByte ?
                            bytes.length - generated
                            :
                            20 - startByte;

            for(i = 0; i < bytesToGen; ++i) {
                bytes[i] = currentBytes[startByte];
                currentBytes[startByte++] = 0;
            }

            this.remCount += bytesToGen;
            generated += bytesToGen;
        }

        while(generated < bytes.length) {
            this.digest.update(this.state);
            currentBytes = this.digest.digest();
            updateState(this.state, currentBytes);
            bytesToGen = bytes.length - generated > 20 ? 20 : bytes.length - generated;

            for(i = 0; i < bytesToGen; ++i) {
                bytes[generated++] = currentBytes[i];
                currentBytes[i] = 0;
            }

            this.remCount += bytesToGen;
        }

        this.remainder = currentBytes;
        this.remCount %= 20;
    }

    @Override
    protected int next(int numBits) {
        int numBytes = (numBits+7)/8;
        byte[] b = new byte[numBytes];
        int next = 0;

        nextBytes(b);
        for (int i = 0; i < numBytes; i++) {
            next = (next << 8) + (b[i] & 0xFF);
        }

        return next >>> (numBytes*8 - numBits);
    }
}
