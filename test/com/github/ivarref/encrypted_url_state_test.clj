(ns com.github.ivarref.encrypted-url-state-test
  (:require [com.github.ivarref.pretty-stuff :as pretty-stuff]
            [clojure.test :as t]
            [theme :as theme]))

(comment
  #_(theme/banner! "Running tests")
  (println "janei (encrypted_url_state.clj:10)")
  (println "test. (encrypted_url_state.clj:10)")
  (println "test. (encrypted_url_state.clj:10) test")
  (println ". (encrypted_url_state.clj:10)")
  (println ".(encrypted_url_state.clj:10)")
  ;(println ". at (encrypted_url_state.clj:10)")

  (println "\033[0;30m.\033[0m (encrypted_url_state.clj:10)")
  (println "This is. , . a test ... /. +_- wooho. (encrypted_url_state.clj:10)"))

(do
  (set! *warn-on-reflection* true)
  (require '[com.github.ivarref.encrypted-url-state :as eus]))

(t/use-fixtures :each pretty-stuff/short-stacktrace)

(defn d
  ([x]
   (println ">>" (pr-str x))
   x)
  ([prefix x]
   (println prefix (pr-str x))
   x))


(t/deftest error-handling-argument-types-encrypt
  (t/is (thrown? IllegalArgumentException (eus/encrypt nil 1 "message")))
  (t/is (thrown? IllegalArgumentException (eus/encrypt "my-key" nil "message")))
  (t/is (thrown? IllegalArgumentException (eus/encrypt "my-key" "123" "message"))))

(t/deftest error-handling-argument-types-decrypt
  (let [encrypted-sample (eus/encrypt "my-key" 1 "message")]
    #_(t/is (= 1 2))
    (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map "my-key" nil encrypted-sample)))
    (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map "my-key" 1 nil)))
    (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map "my-key" 1 123)))
    (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map nil 1 encrypted-sample)))
    (t/is (thrown? IllegalArgumentException (eus/decrypt-to-map ["a" "b"] 1 encrypted-sample)))))

(t/deftest round-trip-happy-case
  ; verify length:
  (t/is (= 60 (count (eus/encrypt "my-key" 1 "message"))))
  (let [enc-1 (eus/encrypt "my-key" 1 "message")
        enc-2 (eus/encrypt "my-key" 1 "message")]
    (t/is (not= enc-1 enc-2))
    (t/is (= {:expired? false, :data "message", :error? false, :error-message nil}
             (eus/decrypt-to-map "my-key" 1 enc-1)))
    (t/is (= {:expired? false, :data "message", :error? false, :error-message nil}
             (eus/decrypt-to-map "my-key" 1 enc-2)))
    (t/is (= {:expired? true, :data nil, :error? true, :error-message "Expired"}
             (eus/decrypt-to-map "my-key" 2 enc-2)))))

(t/deftest round-trip-happy-case-defaults
  ; verify length:
  (t/is (>= (count (eus/encrypt "my-key" "message")) 64))
  (let [enc-1 (eus/encrypt "my-key" "message")
        enc-2 (eus/encrypt "my-key" "message")]
    (t/is (not= enc-1 enc-2))
    (t/is (= {:expired? false, :data "message", :error? false, :error-message nil}
             (eus/decrypt-to-map "my-key" enc-1)))
    (t/is (= {:expired? false, :data "message", :error? false, :error-message nil}
             (eus/decrypt-to-map "my-key" enc-2)))
    (t/is (= {:expired? true, :data nil, :error? true, :error-message "Expired"}
             (binding [eus/-*current-epoch* (fn []
                                              (+ 3601
                                                 (long (/ (System/currentTimeMillis)
                                                          1000))))]
               (eus/decrypt-to-map "my-key" enc-2))))))
