package com.privacylogistics;

/**
 * Format-Preserving Encryption for FF3
 *
 * Copyright (c) 2021 Schoening Consulting LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */
import org.openjdk.jmh.annotations.*;
import java.util.ArrayList;

public class FF3CipherPerf {

    /*public static class CircularList<E> extends ArrayList<E> {
        @Override
        public E get(int index) {
            return super.get(index % size());
        }
    }*/

    /*
     * Benchmark Test
     * ToDo: use non-uniform random strings
     */
    /*@State(Scope.Thread)
    public static class MyState {

        @Setup(Level.Trial)
        public void doSetup() {
            //list = new CircularList<String>();
            alist.add("12345678");
            alist.add("23478436");
            alist.add("99472512");
            alist.add("28830179");
            alist.add("23837374");
        }
        //public CircularList<String> list;
    }*/

    @Benchmark
    @Fork(1)
    @Warmup(iterations = 3)
    public String testEncrypt() throws Exception {
        String key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        String tweak = "D8E7920AFA330A73";
        String plaintext = alist.get(n++%5);
        FF3Cipher c = new FF3Cipher(key, tweak, 10);
        return c.encrypt(plaintext);
    }

    public static int n = 0;
    //public static CircularList<String> list = new CircularList<String>();
    public static ArrayList<String> alist = new ArrayList<String>();
    static {
        alist = new ArrayList<String>();
        alist.add("12345678");
        alist.add("23478436");
        alist.add("99472512");
        alist.add("28830179");
        alist.add("23837374");
    }
}
