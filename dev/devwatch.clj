(ns devwatch
  (:require
    [clj-reload.core :as reload]
    [nextjournal.beholder :as beholder]
    [nrepl.server :as nrepl]
    [theme :as theme]))

(defn clear-screen! []
  (do
    (print "\033[2J\033[3J\033[H")
    (flush)))

(defn on-change [path]
  (clear-screen!)
  (theme/banner! "Reloading")
  (reload/reload {}))

(def watcher
  (beholder/watch on-change "src" "test" "test-resources" "resources"))

(reload/init
  {:dirs   ["src" "test"]
   :output :quiet})


(defn init! [_]
  (clear-screen!)
  (nrepl/start-server
    :bind "127.0.0.1"
    :port 3400)
  (theme/banner! "Starting")
  (require 'com.github.ivarref.encrypted-uri-state)
  (println "Started nrepl://3400")
  @(promise)
  (println "Done"))