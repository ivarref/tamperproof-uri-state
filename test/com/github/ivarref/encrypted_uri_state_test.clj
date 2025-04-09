(ns com.github.ivarref.encrypted-uri-state-test
  (:require [clj-commons.pretty.repl :as pretty]
            [clojure.test :as t]
            [com.github.ivarref.encrypted-uri-state :as eus]
            [theme :as theme])
  (:import (java.util Base64)))

(pretty/install-pretty-exceptions)

(def default-frame-rules
  "The set of rules that forms the default for [[*default-frame-rules*]], and the
  basis for [[*default-frame-filter*]], as a vector of vectors.

 Each rule is a vector of three values:

 * A function that extracts the value from the stack frame map (typically, this is a keyword such
 as :package or :name). The value is converted to a string.
 * A string or regexp used for matching.  Strings must match exactly.
 * A resulting frame visibility (:hide, :omit, :terminate, or :show).

 The default rules:

 * omit everything in `clojure.lang`, `java.lang.reflect`, and the function `clojure.core/apply`
 * hide everything in `sun.reflect`
 * terminate at `speclj.*`, `clojure.main/main*`, `clojure.main/repl/read-eval-print`, or `nrepl.middleware.interruptible-eval`
 "
  [[:package "clojure.lang" :omit]
   [:package #"sun\.reflect.*" :hide]
   [:package "java.lang.reflect" :omit]
   [:name #"speclj\..*" :terminate]
   [:name "clojure.core/apply" :omit]
   [:name #"clojure.*" :omit]
   [:package #"java.*" :omit]
   [:name #"cognitect\.test.*" :omit]
   [:name #"nrepl\.middleware\.interruptible-eval/.*" :terminate]
   [:name #"clojure\.main/repl/read-eval-print.*" :terminate]
   [:name #"clojure\.main/main.*" :terminate]])

(defn short-stacktrace [f]
  (binding [clj-commons.format.exceptions/*default-frame-rules* default-frame-rules]
    (f)))

(t/use-fixtures :each short-stacktrace)

(theme/banner! "Running tests")

(defn d [prefix x]
  (println prefix x)
  x)

(defn- generate-iv-bytes-mock []
  (byte-array [(byte 1)
               (byte 2)
               (byte 3)
               (byte 4)
               (byte 5)
               (byte 6)
               (byte 7)
               (byte 8)
               (byte 9)
               (byte 10)
               (byte 11)
               (byte 12)]))

(defn- generate-iv-bytes-mock-2 []
  (byte-array (vec (reverse [(byte 1)
                             (byte 2)
                             (byte 3)
                             (byte 4)
                             (byte 5)
                             (byte 6)
                             (byte 7)
                             (byte 8)
                             (byte 9)
                             (byte 10)
                             (byte 11)
                             (byte 12)]))))

(def secret-key ["my-key" "my-salt"])

(def decrypt-to-vec (resolve 'com.github.ivarref.encrypted-uri-state/decrypt-to-vec))

(def encrypted-2 "DAsKCQgHBgUEAwIBYB_uNgCNyB-0F1c9F0lgcXffanWSfU7EvEEOqIPgNdlCDicJpj4bxuGHqfqcMY0=")

(t/deftest ^:ignore basics
  (with-redefs [eus/generate-iv-bytes generate-iv-bytes-mock]
    (t/is (= "AQIDBAUGBwgJCgsMM2RxoI-hI7WTG0K8eHlrmiHhXT_67UhoYuLJWrjkc20Aen98kBg5hzQXttnFNoI="
             (eus/encrypt secret-key 1 "my-super-duper-great-message\n"))))
  (with-redefs [eus/generate-iv-bytes generate-iv-bytes-mock-2]
    (t/is (= encrypted-2
             (eus/encrypt secret-key 1 "my-super-duper-great-message\n"))))
  (t/is (= [1 "my-super-duper-great-message\n"]
          (decrypt-to-vec secret-key encrypted-2)))
  (t/is (= {:expired? false
            :state "my-super-duper-great-message\n"}
           (eus/decrypt-to-map secret-key 1 encrypted-2)))
  (t/is (= true
           (:expired? (eus/decrypt-to-map secret-key 2 encrypted-2))))
  (t/is (= {:expired? true
            :state nil}
           (eus/decrypt-to-map secret-key 2 encrypted-2))))

(t/deftest error-handling-argument-types-decrypt
  #_(t/is (thrown? IllegalArgumentException (eus/decrypt-to-map nil 1 encrypted-2)))
  (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map secret-key nil encrypted-2)))
  (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map secret-key 1 nil)))
  (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map secret-key 1 123))))
  ;(t/is (thrown? IllegalArgumentException (eus/decrypt-to-map secret-key 1 "")))
  ;(t/is (thrown? IllegalArgumentException (eus/decrypt-to-map secret-key 1 ".åååasdf.asdf.asdfasdfasdf./asdfasdf/"))))

(defn- print-str-bytes [byts]
  (let [byts (.decode (Base64/getUrlDecoder) ^String byts)]
    (dotimes [i (alength #^bytes byts)]
      (print (format "%02x" (byte (aget #^bytes byts i))))
      (print " ")))
  (println "")
  (flush))


(defn decrypt [ky now-epoch-seconds encrypted]
  (:state (eus/decrypt-to-map ky now-epoch-seconds encrypted)))

(t/deftest round-trip-happy-case
  (let [enc-1 (eus/encrypt secret-key 1 "message")
        enc-2 (eus/encrypt secret-key 1 "message")]
    (t/is (not= enc-1 enc-2))

    (t/is (= "message" (:state (eus/decrypt-to-map secret-key 1 enc-1))))
    (t/is (= "message" (:state (eus/decrypt-to-map secret-key 1 enc-2))))

    (t/is (= false (:expired? (eus/decrypt-to-map secret-key 1 enc-2))))
    (t/is (= true (:expired? (eus/decrypt-to-map secret-key 2 enc-2))))
    (t/is (= true (:error? (eus/decrypt-to-map secret-key 1 "AQIDBAUGBwgJCgsMM2RxoI-hI7WTG0K8eHlrmiHhXT_67UhoYuLJWrjkc20Aen98kBg5hzQXttnFNoI="))))
    (t/is (= true (:error? (eus/decrypt-to-map secret-key 1 "AQIDBAUGBwgJCgsMM2RxoI-hI7WTG0K8eHlrmihXT_67UhoYuLJWrjkc20Aen98kBg5hzQXttnFNoI="))))
    #_(let [seen (atom #{})]
        (dotimes [x 10]
          (let [encrypted (eus/encrypt secret-key 1 "message")]
               (println (:error-message (eus/decrypt-to-map ["1" "2"] 1 encrypted))))))))
  ;(t/is (= "my-super-duper-great-message\n" (:state (eus/decrypt-to-map secret-key 1 (eus/encrypt secret-key 1 "my-super-duper-great-message\n")))))
  ;(print-str-bytes (eus/encrypt secret-key 1 "my-super-duper-great-message\n"))
  ;(print-str-bytes (eus/encrypt secret-key 1 "my-super-duper-great-message\n")))

#_(t/deftest unsign-to-map-test
    (let [state "my-super-duper-great-message\n"
          signed (tus/sign "my-key" 1 state)]

      (t/is (= {:tampered? false :expired? false :state state} (tus/unsign-to-map "my-key" 1 signed)))
      (t/is (= {:tampered? false :expired? true :state nil} (tus/unsign-to-map "my-key" 2 signed)))
      (t/is (= {:tampered? true :expired? false :state nil} (tus/unsign-to-map "my-kyz" 1 signed)))
      (t/is (= {:tampered? true :expired? true :state nil} (tus/unsign-to-map "my-kyz" 2 signed)))))
