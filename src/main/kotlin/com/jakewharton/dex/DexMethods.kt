package com.jakewharton.dex

import com.android.dex.Dex
import com.android.dex.Annotation
import com.android.dex.DexFormat
import com.android.dex.MethodId
import com.android.dx.cf.direct.DirectClassFile
import com.android.dx.cf.direct.StdAttributeFactory
import com.android.dx.dex.DexOptions
import com.android.dx.dex.cf.CfOptions
import com.android.dx.dex.cf.CfTranslator
import com.android.dx.dex.file.DexFile
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.util.ArrayList
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/** Extract method references from dex bytecode. */
class DexMethods private constructor() {
  companion object {
    private val CLASS_MAGIC = byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte())
    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00)

    @JvmStatic fun main(vararg args: String) {
      val hideSyntheticNumbers = args.contains("--hide-synthetic-numbers")
      args.filter { !it.startsWith("--") }
          .map { FileInputStream(it) }
          .defaultIfEmpty(System.`in`)
          .map { it.use { it.readBytes() } }
          .toList()
          .let { list(it) }
          .map { it.render(hideSyntheticNumbers) }
          .forEach { println(it) }
    }

    /** List method references in the files of any `.dex`, `.class`, `.jar`, `.aar`, or `.apk`. */
    @JvmStatic fun list(vararg files: File) = list(files.map { it.readBytes() })

    /** List method references in the bytes of any `.dex`, `.class`, `.jar`, `.aar`, or `.apk`. */
    @JvmStatic fun list(bytes: ByteArray) = list(listOf(bytes))

    /** List method references in the bytes of any `.dex`, `.class`, `.jar`, `.aar`, or `.apk`. */
    @JvmStatic fun list(bytes: Iterable<ByteArray>): List<DexMethod> {
      val collection = bytes
          .fold(ClassAndDexCollection()) { collection, bytes ->
            if (bytes.startsWith(DEX_MAGIC)) {
              collection.dexes += bytes
            } else if (bytes.startsWith(CLASS_MAGIC)) {
              collection.classes += bytes
            } else {
              ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
                zis.entries().forEach {
                  if (it.name.endsWith(".dex")) {
                    collection.dexes += zis.readBytes()
                  } else if (it.name.endsWith(".class")) {
                    collection.classes += zis.readBytes()
                  } else if (it.name.endsWith(".jar")) {
                    ZipInputStream(ByteArrayInputStream(zis.readBytes())).use { jar ->
                      jar.entries().forEach {
                        if (it.name.endsWith(".class")) {
                          collection.classes += jar.readBytes()
                        }
                      }
                    }
                  }
                }
              }
            }

            collection // Pass along the mutable reference.
          }

      if (collection.classes.isNotEmpty()) {
        collection.dexes += classesToDex(collection.classes)
      }
      return collection.dexes
          .map { Dex(it) }
          .flatMap { dex -> dex.methodIds().map { toMethod(dex, it) } }
          .sorted()
    }

    private fun classesToDex(bytes: List<ByteArray>): ByteArray {
      val dexOptions = DexOptions()
      dexOptions.targetApiLevel = DexFormat.API_NO_EXTENDED_OPCODES
      val dexFile = DexFile(dexOptions)

      bytes.forEach {
        val cf = DirectClassFile(it, "None.class", false)
        cf.setAttributeFactory(StdAttributeFactory.THE_ONE)
        CfTranslator.translate(cf, it, CfOptions(), dexOptions, dexFile)
      }

      return dexFile.toDex(null, false)
    }

    private fun toMethod(dex: Dex, methodId: MethodId): DexMethod {
      val declaringType = humanName(dex.typeNames()[methodId.declaringClassIndex])
      val name = dex.strings()[methodId.nameIndex]
      System.out.println("classOffset" + dex.classDefs())
      try {
        val annotationSetOffset = getAnnotationSetOffset(dex, methodId)
        if (annotationSetOffset != 0) {
          val setIn = dex.open(annotationSetOffset) // annotation_set_item
          var i = 0
          val size = setIn.readInt()
          System.out.println("Size: $size")
          while (i < size) {
            val annotationOffset = setIn.readInt()
            val annotationIn = dex.open(annotationOffset) // annotation_item
            val candidate = annotationIn.readAnnotation()
            val reader = candidate.reader
            val fieldCount = reader.readAnnotation()
            System.out.println("FC: $candidate $fieldCount")
            val annotationType = reader.getAnnotationType();
            var j = 0
            while (j < fieldCount) {
              val anameIndex = reader.readAnnotationName();
              val aname = dex.strings()[anameIndex]
              reader.skipValue()
              System.out.println("NAME: $annotationType $aname ")
              j++
            }
            i++
          }
        }
      } catch (e: Exception) {
        e.printStackTrace()
      }

      val methodProtoIds = dex.protoIds()[methodId.protoIndex]
      val parameterTypes = dex.readTypeList(methodProtoIds.parametersOffset).types
          .map { dex.typeNames()[it.toInt()] }
          .map { humanName(it) }
      val returnType = humanName(dex.typeNames()[methodProtoIds.returnTypeIndex])
      return DexMethod(declaringType, name, parameterTypes, returnType)
    }

    private fun getAnnotationSetOffset(dex: Dex, methodId: MethodId): Int {
      val directoryOffset = dex.annotationDirectoryOffsetFromClassDefIndex(methodId.declaringClassIndex)
      if (directoryOffset == 0) {
        return 0 // nothing on this class has annotations
      }
      val directoryIn = dex.open(directoryOffset)
      val classSetOffset = directoryIn.readInt()
      val fieldsSize = directoryIn.readInt()
      val methodsSize = directoryIn.readInt()
      directoryIn.readInt() // parameters size
      for (i in 0..fieldsSize - 1) {
        val candidateFieldIndex = directoryIn.readInt()
        val annotationSetOffset = directoryIn.readInt()
      }
      for (i in 0..methodsSize - 1) {
        val candidateMethodIndex = directoryIn.readInt()
        val annotationSetOffset = directoryIn.readInt()
        if (candidateMethodIndex == methodId.protoIndex) {
          return annotationSetOffset;
        }
      }
      return 0
    }

    private fun humanName(type: String): String {
      if (type.startsWith("[")) {
        return humanName(type.substring(1)) + "[]"
      }
      if (type.startsWith("L")) {
        return type.substring(1, type.length - 1).replace('/', '.')
      }
      return when (type) {
        "B" -> "byte"
        "C" -> "char"
        "D" -> "double"
        "F" -> "float"
        "I" -> "int"
        "J" -> "long"
        "S" -> "short"
        "V" -> "void"
        "Z" -> "boolean"
        else -> throw IllegalArgumentException("Unknown type $type")
      }
    }

    private fun <T> List<T>.defaultIfEmpty(value: T): List<T> {
      return if (isNotEmpty()) this else listOf(value)
    }

    private fun ByteArray.startsWith(value: ByteArray): Boolean {
      if (value.size > size) return false
      value.forEachIndexed { i, byte ->
        if (get(i) != byte) {
          return false
        }
      }
      return true
    }

    private fun ZipInputStream.entries(): Sequence<ZipEntry> {
      return object : Sequence<ZipEntry> {
        override fun iterator(): Iterator<ZipEntry> {
          return object : Iterator<ZipEntry> {
            var next: ZipEntry? = null

            override fun hasNext(): Boolean {
              next = nextEntry
              return next != null
            }

            override fun next() = next!!
          }
        }
      }
    }

    internal class ClassAndDexCollection {
      val classes = ArrayList<ByteArray>()
      val dexes = ArrayList<ByteArray>()
    }
  }
}
