require 'xcodeproj'
require 'pathname'

root = File.expand_path('..', __dir__)
%w[ios macos].each do |platform|
  base = File.join(root, 'demo/provider_app', platform)
  project = Xcodeproj::Project.open(File.join(base, 'Runner.xcodeproj'))
  target = project.targets.find { |t| t.name == 'Runner' }
  relative = Pathname.new(File.join(root, 'native/apple/Keypass.swift')).relative_path_from(Pathname.new(base)).to_s
  ref = project.files.find { |f| f.path == relative } || project.main_group.new_file(relative)
  target.source_build_phase.add_file_reference(ref, true)
  target.build_configurations.each do |config|
    settings = config.build_settings
    settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'dev.keypass.providerDemo'
    settings['DEVELOPMENT_TEAM'] = '5AHFA9FUZG'
    settings['CODE_SIGN_STYLE'] = 'Automatic'
    settings['CODE_SIGN_IDENTITY'] = 'Apple Development'
    settings['SWIFT_VERSION'] = '5.0'
    # Demo executables expose the linked C ABI to DynamicLibrary.process().
    settings['DEAD_CODE_STRIPPING'] = 'NO'
    settings['STRIP_INSTALLED_PRODUCT'] = 'NO'
    settings['OTHER_LDFLAGS'] = ['$(inherited)', '-Wl,-export_dynamic']
    if platform == 'ios'
      settings['IPHONEOS_DEPLOYMENT_TARGET'] = '18.0'
      settings['CODE_SIGN_ENTITLEMENTS'] = 'Runner/Runner.entitlements'
    else
      settings['MACOSX_DEPLOYMENT_TARGET'] = '15.0'
    end
  end
  project.build_configurations.each do |config|
    config.build_settings[platform == 'ios' ? 'IPHONEOS_DEPLOYMENT_TARGET' : 'MACOSX_DEPLOYMENT_TARGET'] =
      platform == 'ios' ? '18.0' : '15.0'
  end
  if platform == 'ios'
    package_path = '../../../native/hardware_apple'
    package = project.root_object.package_references.find { |p|
      p.isa == 'XCLocalSwiftPackageReference' && p.relative_path == package_path
    }
    unless package
      package = project.new(Xcodeproj::Project::Object::XCLocalSwiftPackageReference)
      package.relative_path = package_path
      project.root_object.package_references << package
    end
    product = target.package_product_dependencies.find { |p| p.product_name == 'KeypassHardwareApple' }
    unless product
      product = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
      product.product_name = 'KeypassHardwareApple'
      product.package = package
      target.package_product_dependencies << product
    end
    unless target.frameworks_build_phase.files.any? { |f| f.product_ref == product }
      build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
      build_file.product_ref = product
      target.frameworks_build_phase.files << build_file
    end
  end
  project.save
end
