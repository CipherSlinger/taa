// Benign Scala: a small statistics helper. No TAA family fires on this file.
package com.example

import scala.collection.mutable

final case class Reading(sensor: String, celsius: Double)

final class Averager(capacity: Int) {
  private val readings = mutable.ArrayBuffer.empty[Reading]

  def add(reading: Reading): Unit = {
    if (readings.size >= capacity) {
      readings.remove(0)
    }
    readings += reading
  }

  def mean: Option[Double] = {
    if (readings.isEmpty) None
    else Some(readings.map(_.celsius).sum / readings.size)
  }

  def summary: String = {
    mean match {
      case Some(value) => f"mean=$value%.2f over ${readings.size} readings"
      case None        => "no readings"
    }
  }
}

object Main {
  def main(args: Array[String]): Unit = {
    val averager = new Averager(8)
    averager.add(Reading("kitchen", 21.5))
    averager.add(Reading("study", 19.75))
    println(averager.summary)
  }
}
