package org.pushgate.phone

import android.os.Bundle
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.Size
import kotlin.math.min

/**
 * Portrait-locked enrollment QR capture screen. Reuses zxing's robust
 * [CaptureActivity]/CaptureManager camera lifecycle, but the app overrides
 * `zxing_barcode_scanner.xml` to use [QrFinderView] (square finder, corner
 * brackets, no laser). The framing region is constrained to a centered square so
 * it presents as an upright QR scanner rather than a landscape barcode scanner.
 */
class QrCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The only screen that blocks screenshots: the camera preview shows the one-time
        // enrollment code. Home, Settings, History and the approval screens allow capture.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun initializeContent(): DecoratedBarcodeView {
        val view = super.initializeContent()
        val metrics = resources.displayMetrics
        val square = (min(metrics.widthPixels, metrics.heightPixels) * 0.72f).toInt()
        view.barcodeView.framingRectSize = Size(square, square)
        return view
    }
}
