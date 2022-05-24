<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit08cc3fe921cc35c1c814cc6f3f036a16
{
    public static $prefixLengthsPsr4 = array (
        'l' => 
        array (
            'luwc\\' => 5,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'luwc\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src/luwc',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit08cc3fe921cc35c1c814cc6f3f036a16::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit08cc3fe921cc35c1c814cc6f3f036a16::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit08cc3fe921cc35c1c814cc6f3f036a16::$classMap;

        }, null, ClassLoader::class);
    }
}
