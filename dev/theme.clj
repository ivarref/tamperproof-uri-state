(ns theme
  (:require [clojure.string :as str])
  (:import (java.util Random)))

(def ^:private desert-life ["🌵", "🏜", "️🐪", "🐫", "⚱️", "🦂", "🦡", "☀️", "🐍"])
(def ^:private marine-life ["🐳", "🐠", "🦈", "🐙", "🐡", "🐬", "🐟", "🦀", "🐋"])
;                  1     2     3     4     5     6     7      8     9

(def ^:private desert-colors ["#DD692C"
                              "#D48662"
                              "#D9C3A9"
                              "#D9B6A3"
                              "#BF754B"
                              "#BF9B7A"
                              "#C16630"
                              "#A6583C"
                              "#A67458"
                              "#734434"
                              "#723715"
                              "#734B34"
                              "#732F17"
                              "#783215"
                              "#8B322C"])
(def ^:private marine-colors ["#0064C8"
                              "#0A6ED3"
                              "#1478DC"
                              "#1E82E6"
                              "#288CF0"
                              "#3296FA"
                              "#3CA0FF"
                              "#46AAFF"
                              "#50B4FF"
                              "#5ABEFF"
                              "#64C8FF"
                              "#6ED2FF"
                              "#78DCFF"
                              "#82E6FF"
                              "#8CF0FF"])

(defn- next-int [seed bound]
  (.nextInt
    (Random. (long (.nextDouble (Random. seed) Long/MAX_VALUE)))
    bound))

(defn- next-double [seed]
  (.nextDouble
    (Random. (long (.nextDouble (Random. seed) Long/MAX_VALUE)))))

(defn- random-choice [seed vvec]
  (nth vvec (next-int seed (count vvec))))

(defn- gen-block [seed life-vec life-chance]
  (assert (>= life-chance 0))
  (assert (<= life-chance 1))
  (if (< (next-double seed) life-chance)
    (let [idx (next-int seed (count life-vec))]
      (assert (>= idx 0))
      (assert (< idx (count life-vec)))
      [(str idx) (str idx) "."])
    ["." "." "."]))

(defn- gen-marine [seed life-vec life-chance max-length]
  (loop [i 0
         buf []]
    (if (< i (inc max-length))
      (recur (inc i) (into buf (gen-block (+ i seed) life-vec life-chance)))
      buf)))

(defn- parse-hex [hx]
  (assert (= 2 (count hx)))
  (let [mapp {"0" 0 "1" 1 "2" 2 "3" 3 "4" 4 "5" 5 "6" 6 "7" 7 "8" 8 "9" 9
              "A" 10 "B" 11 "C" 12 "D" 13 "E" 14 "F" 15
              "a" 10 "b" 11 "c" 12 "d" 13 "e" 14 "f" 15}
        high-nibble (str (nth hx 0))
        low-nibble (str (nth hx 1))]
    (assert (contains? mapp high-nibble))
    (assert (contains? mapp low-nibble))
    (str (+
           (* 16 (get mapp high-nibble))
           (get mapp low-nibble)))))

(defn- hex-str-to-ansi [hstr]
  (assert (string? hstr))
  (assert (= 7 (count hstr)))
  (assert (str/starts-with? hstr "#"))
  (let [r (parse-hex (subs hstr 1 3))
        g (parse-hex (subs hstr 3 5))
        b (parse-hex (subs hstr 5 7))]
    (str "\033[38;2;" r ";" g ";" b "m" "≈\033[0m")))

(def ^:private themes {:desert [desert-colors desert-life]
                       :marine [marine-colors marine-life]})

(defn gen-theme-line [theme max-length & [life-chance seed]]
  (assert (contains? #{:desert :marine} theme))
  (let [[background life] (get themes theme)
        life-chance (or life-chance 0.5)
        seed (or seed (rand-int 1000000))
        add (mod seed 3)
        new-seed (quot seed 3)
        str-marine (gen-marine new-seed life life-chance max-length)
        lin1 (str/join "" (loop [i 0
                                 buf []]
                            (if (< i max-length)
                              (recur (+ i 2)
                                     (into buf [(nth str-marine (+ i add))
                                                (nth str-marine (+ 1 i add))]))
                              buf)))
        lin2 (loop [s lin1
                    idx 0]
               (if (< idx (count life))
                 (recur
                   (-> s
                       (str/replace (str idx idx) "##")
                       (str/replace (str idx) ".")
                       (str/replace "##" (str idx idx)))
                   (inc idx))
                 s))
        lin3 (loop [idx 0
                    char-count 0
                    lin ""]
               (if (= char-count max-length)
                 lin
                 (if (= idx (dec (count lin2)))             ; end of line
                   (recur (inc idx)
                          (inc char-count)
                          (str lin (hex-str-to-ansi (random-choice (+ idx seed) background))))
                   (let [c (str (nth lin2 idx))]
                     (if (or (= c ".")
                             (> (+ 2 char-count) max-length))
                       (recur (inc idx) (inc char-count) (str lin (hex-str-to-ansi (random-choice (+ idx seed) background))))
                       (recur (+ 2 idx) (+ 2 char-count) (str lin (str (nth life (parse-long c))))))))))]
    lin3))

(defn demo! [_]
  (let [rnd (rand-int 1000000)]
    (dotimes [i 15]
      (println (gen-theme-line :desert 80 0.35 (+ rnd i))))))

(defn banner! [txt]
  (println (str (gen-theme-line :desert 32 0.3)
                (str " … " txt " … ")
                (gen-theme-line :desert 32 0.3))))