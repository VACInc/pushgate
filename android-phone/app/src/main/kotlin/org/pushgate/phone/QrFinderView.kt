package org.pushgate.phone

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import com.journeyapps.barcodescanner.ViewfinderView

/**
 * QR-style finder overlay used by the enrollment scanner. Extends zxing's
 * [ViewfinderView] but overrides drawing to dim outside the (square) framing
 * rectangle and draw rounded corner brackets — with NO horizontal "laser" line,
 * so it reads as a QR scanner rather than a 1D barcode scanner.
 */
class QrFinderView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : ViewfinderView(context, attrs) {

    private val bracketPaint = Paint().apply {
        color = 0xFFFFFFFF.toInt()
        style = Paint.Style.STROKE
        strokeWidth = context.resources.displayMetrics.density * 4f
        strokeCap = Paint.Cap.ROUND
        isAntiAlias = true
    }

    override fun onDraw(canvas: Canvas) {
        refreshSizes()
        val frame = framingRect ?: return
        val width = canvas.width.toFloat()
        val height = canvas.height.toFloat()

        // Dim everything outside the framing square (no laser line).
        paint.color = if (resultBitmap != null) resultColor else maskColor
        canvas.drawRect(0f, 0f, width, frame.top.toFloat(), paint)
        canvas.drawRect(0f, frame.top.toFloat(), frame.left.toFloat(), (frame.bottom + 1).toFloat(), paint)
        canvas.drawRect((frame.right + 1).toFloat(), frame.top.toFloat(), width, (frame.bottom + 1).toFloat(), paint)
        canvas.drawRect(0f, (frame.bottom + 1).toFloat(), width, height, paint)

        // Corner brackets on the square.
        val len = frame.width() * 0.14f
        drawCorner(canvas, frame.left.toFloat(), frame.top.toFloat(), len, 1, 1)
        drawCorner(canvas, frame.right.toFloat(), frame.top.toFloat(), len, -1, 1)
        drawCorner(canvas, frame.left.toFloat(), frame.bottom.toFloat(), len, 1, -1)
        drawCorner(canvas, frame.right.toFloat(), frame.bottom.toFloat(), len, -1, -1)

        // Keep redrawing while the preview is live (mirrors ViewfinderView cadence).
        postInvalidateDelayed(80L, frame.left, frame.top, frame.right, frame.bottom)
    }

    private fun drawCorner(canvas: Canvas, x: Float, y: Float, len: Float, sx: Int, sy: Int) {
        canvas.drawLine(x, y, x + sx * len, y, bracketPaint)
        canvas.drawLine(x, y, x, y + sy * len, bracketPaint)
    }
}
