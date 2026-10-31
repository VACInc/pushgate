package org.pushgate.phone

import android.app.Application

/** Runs at every process start, including a cold start for a background push. */
class PushGateApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        DebugLog.onProcessStart(this)
    }
}
