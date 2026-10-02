#!/usr/bin/env ruby
# Development-only Xcode generator; requires the xcodeproj Ruby gem.
require 'xcodeproj'
require 'fileutils'
require 'pathname'
root = File.expand_path('..', __dir__)
domain = ENV.fetch('KEYPASS_DEMO_DOMAIN')
team = ENV.fetch('KEYPASS_DEMO_TEAM_ID')
bundle = ENV.fetch('KEYPASS_DEMO_BUNDLE_ID', 'dev.keypass.demo')
abort 'Expected a DNS hostname' unless domain.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/) && domain.include?('.') && !domain.include?('..')
abort 'Expected an Apple Team ID' unless team.match?(/\A[A-Z0-9]{10}\z/)
output = File.join(root, 'build/demo-xcode')
FileUtils.mkdir_p(output)
Xcodeproj::Plist.write_to_path({
  'CFBundleIdentifier' => '$(PRODUCT_BUNDLE_IDENTIFIER)',
  'CFBundleExecutable' => '$(EXECUTABLE_NAME)',
  'CFBundleName' => 'Keypass Demo', 'CFBundleDisplayName' => 'Keypass Demo',
  'CFBundlePackageType' => 'APPL', 'CFBundleVersion' => '1',
  'CFBundleShortVersionString' => '0.1', 'LSMinimumSystemVersion' => '15.0',
  'KeypassDomain' => domain, 'NSHighResolutionCapable' => true,
}, File.join(output, 'Info.plist'))
Xcodeproj::Plist.write_to_path({
  'com.apple.developer.associated-domains' => ["webcredentials:#{domain}"],
}, File.join(output, 'KeypassDemo.entitlements'))
project = Xcodeproj::Project.new(File.join(output, 'KeypassDemo.xcodeproj'))
target = project.new_target(:application, 'KeypassDemo', :osx, '15.0')
['native/apple/Keypass.swift', 'native/apple/DemoHost/main.swift'].each do |source|
  target.add_file_references([project.main_group.new_file(File.join(root, source))])
end
worker = project.main_group.new_file(File.join(output, 'keypass-demo-worker'))
copy = target.new_copy_files_build_phase('Embed Dart worker')
copy.dst_subfolder_spec = '7' # Resources
copy.add_file_reference(worker).settings = {'ATTRIBUTES' => ['CodeSignOnCopy']}
target.build_configurations.each do |config|
  config.build_settings.merge!({
    'PRODUCT_NAME' => 'Keypass Demo', 'EXECUTABLE_NAME' => 'KeypassDemo',
    'PRODUCT_BUNDLE_IDENTIFIER' => bundle, 'DEVELOPMENT_TEAM' => team,
    'CODE_SIGN_STYLE' => 'Automatic', 'CODE_SIGN_IDENTITY' => 'Apple Development',
    'CODE_SIGN_ENTITLEMENTS' => File.join(output, 'KeypassDemo.entitlements'),
    'INFOPLIST_FILE' => File.join(output, 'Info.plist'),
    'GENERATE_INFOPLIST_FILE' => 'NO', 'SWIFT_VERSION' => '5.0',
    'ARCHS' => 'arm64', 'ONLY_ACTIVE_ARCH' => 'YES',
    'ENABLE_APP_SANDBOX' => 'NO', 'ENABLE_HARDENED_RUNTIME' => 'NO',
    'COMBINE_HIDPI_IMAGES' => 'YES', 'LD_RUNPATH_SEARCH_PATHS' => '$(inherited) @executable_path/../Frameworks',
  })
end
project.root_object.attributes['TargetAttributes'] = {
  target.uuid => {'DevelopmentTeam' => team, 'ProvisioningStyle' => 'Automatic',
                  'SystemCapabilities' => {'com.apple.AssociatedDomains' => {'enabled' => 1}}},
}
project.save
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(target)
scheme.set_launch_target(target)
scheme.save_as(project.path, 'KeypassDemo', true)
puts project.path
