package com.lauriewired.util;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;

public class ThreadUtils {

    /**
     * Executes a runnable on the Swing Event Dispatch Thread.
     * If the current thread is already the EDT, it executes immediately.
     * If not, it waits for the execution to finish before returning.
     */
    public static void invokeAndWaitSafe(Runnable runnable) throws InvocationTargetException, InterruptedException {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }
}