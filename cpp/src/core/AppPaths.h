#pragma once

#include <QString>

namespace nt {

class AppPaths {
public:
    static QString appName();
    static QString appDataDir();
    static QString dataDir();
    static QString snapshotDir();
    static QString vendorDbPath();
    static QString vendorSeedPath();
    static QString bundledToolPath(const QString& name);
    static QString settingsPath();
    static void ensureRuntimeTree();
};

} // namespace nt
