package co.strobes.bridge

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Off-device unit tests for the destructive-command policy — the guard that
 * stops a cloud agent from rebooting/wiping/self-uninstalling the device it's
 * driving over the remote bridge (see ShellCommandRouter.classifyDestructive).
 * classifyDestructive is intentionally pure so this needs no device.
 */
class ShellCommandRouterDestructiveTest {

    private fun blocked(cmd: String) =
        assertNotNull("expected BLOCKED: `$cmd`", ShellCommandRouter.classifyDestructive(cmd))

    private fun allowed(cmd: String) =
        assertNull("expected ALLOWED: `$cmd`", ShellCommandRouter.classifyDestructive(cmd))

    @Test fun blocksPowerAndLifecycle() {
        blocked("reboot")
        blocked("reboot recovery")
        blocked("su -c reboot")
        blocked("/system/bin/reboot")
        blocked("shutdown -h now")
        blocked("svc power reboot")
        blocked("poweroff")
    }

    @Test fun blocksFactoryWipe() {
        blocked("recovery --wipe_data")
        blocked("am broadcast -a android.intent.action.MASTER_CLEAR")
        blocked("fastboot -w")
    }

    @Test fun blocksRootFilesystemDeletionOnly() {
        blocked("rm -rf /")
        blocked("rm -rf /system")
        blocked("rm -rf /data")
        blocked("rm -rf /sdcard/")
        blocked("rm -rf /data/*")
        // ...but scoped deletes are ordinary pentest work and must pass.
        allowed("rm -rf /data/local/tmp/work")
        allowed("rm -rf /sdcard/Download/capture")
        allowed("rm /data/local/tmp/foo.txt")
    }

    @Test fun blocksBridgeSelfRemovalOnly() {
        blocked("pm uninstall co.strobes.bridge")
        blocked("pm clear co.strobes.bridge")
        blocked("pm disable-user co.strobes.bridge")
        // Uninstalling a *target* app is exactly what the bridge is for.
        allowed("pm uninstall com.example.target")
        allowed("pm clear com.example.target")
    }

    @Test fun blocksSmuggledCompoundCommands() {
        blocked("echo hi && reboot")
        blocked("id; rm -rf /system")
        blocked("true || poweroff")
        blocked("ls | reboot")
    }

    @Test fun blocksBlockDeviceDestruction() {
        blocked("mkfs.ext4 /dev/block/sda1")
        blocked("dd if=/dev/zero of=/dev/block/bootdevice")
        // dd to a normal file is fine.
        allowed("dd if=/sdcard/a of=/sdcard/b")
    }

    @Test fun allowsOrdinaryCommands() {
        allowed("id")
        allowed("pm list packages -3")
        allowed("input tap 100 200")
        allowed("screencap -p /sdcard/s.png")
        allowed("am start -n com.example/.Main")
        allowed("cat /data/local/tmp/out.txt")
    }
}
