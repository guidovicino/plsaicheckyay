#!/usr/bin/env python3

"""
Test script for plsaicheckyay functionality
This demonstrates how the security analysis would work
"""

import sys
import os

# Add current directory to path to import our module
sys.path.insert(0, os.path.dirname(__file__))

from plsaicheckyay import PKGBUILDInfo, OllamaProvider, SecurityAnalysis


def test_repository_detection():
    """Test AUR vs Official repository detection"""
    from plsaicheckyay import YayWrapper, OllamaProvider
    
    provider = OllamaProvider()
    wrapper = YayWrapper(provider)
    
    # Test with known official packages
    official_packages = ["firefox", "git", "python"]
    print("🏛️ Testing Official Repository Detection:")
    for pkg in official_packages:
        is_aur = wrapper._is_aur_package(pkg)
        print(f"  {pkg}: {'AUR' if is_aur else 'Official'} ({'❌' if is_aur else '✅'})")
    
    print()

def test_pkgbuild_analysis():
    """Test PKGBUILD security analysis with sample data"""
    
    # Sample PKGBUILD content (simplified for testing)
    sample_pkgbuild = """
pkgname=test-package
pkgver=1.0.0
pkgrel=1
pkgdesc="A test package"
arch=('x86_64')
url="https://example.com"
license=('MIT')
source=("https://github.com/example/test-package/archive/v$pkgver.tar.gz")
sha256sums=('abc123...')

build() {
    cd "$pkgname-$pkgver"
    make
}

package() {
    cd "$pkgname-$pkgver"
    make DESTDIR="$pkgdir" install
}
"""
    
    # Create PKGBUILDInfo object
    pkgbuild_info = PKGBUILDInfo(
        pkgname="test-package",
        pkgver="1.0.0",
        source=["https://github.com/example/test-package/archive/v1.0.0.tar.gz"],
        url="https://example.com",
        content=sample_pkgbuild,
        is_aur_package=True
    )
    
    print("🧪 Testing PKGBUILD Analysis")
    print(f"Package: {pkgbuild_info.pkgname} v{pkgbuild_info.pkgver}")
    print(f"URL: {pkgbuild_info.url}")
    print(f"Sources: {', '.join(pkgbuild_info.source)}")
    print()
    
    # Test with OLLAMA provider (this will fail if OLLAMA is not running)
    try:
        print("🤖 Testing OLLAMA analysis...")
        provider = OllamaProvider()
        analysis = provider.analyze_pkgbuild(pkgbuild_info)
        
        print("✅ Analysis completed!")
        print(f"Confidence: {analysis.confidence_score:.1%}")
        print(f"Safe: {'Yes' if analysis.safe_to_install else 'No'}")
        print(f"Recommendation: {analysis.recommendation}")
        
        if analysis.risks:
            print("Risks found:")
            for risk in analysis.risks:
                print(f"  • {risk}")
        
        if analysis.warnings:
            print("Warnings:")
            for warning in analysis.warnings:
                print(f"  • {warning}")
                
    except Exception as e:
        print(f"❌ OLLAMA test failed: {e}")
        print("Make sure OLLAMA is running with: ollama serve")
    
    print("\n🎯 Test completed!")


if __name__ == "__main__":
    test_repository_detection()
    test_pkgbuild_analysis()