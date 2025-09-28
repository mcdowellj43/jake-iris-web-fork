#!/usr/bin/env python3
"""
Test script for Phase 1 IOC Enrichment Implementation
Validates that all components work correctly
"""

import sys
import os
import traceback
from pathlib import Path

# Add the source directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'source'))

def test_imports():
    """Test that all modules can be imported"""
    print("🔍 Testing imports...")

    try:
        # Test core enrichment imports
        from app.iris_engine.enrichment import ProfileManager, load_profiles, EnrichmentNormalizer, MarkdownRenderer
        print("✅ Core enrichment imports successful")

        # Test source imports
        from app.iris_engine.enrichment.sources import EnrichmentSourceBase, SOURCES
        from app.iris_engine.enrichment.sources.abuseipdb import AbuseIPDB
        from app.iris_engine.enrichment.sources.greynoise import GreyNoise
        from app.iris_engine.enrichment.sources.virustotal import VirusTotal
        print("✅ Source imports successful")

        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        traceback.print_exc()
        return False

def test_profile_system():
    """Test the profile management system"""
    print("\n🔍 Testing profile system...")

    try:
        from app.iris_engine.enrichment.profiles import ProfileManager, get_profile, list_profiles

        # Test profile manager creation
        pm = ProfileManager()
        pm.load_profiles()
        print("✅ Profile manager initialized")

        # Test default profiles
        profiles = list_profiles()
        expected_profiles = ['IP-basic', 'Domain-basic', 'Hash-basic']

        for profile_name in expected_profiles:
            if profile_name in profiles:
                profile = get_profile(profile_name)
                print(f"✅ Profile '{profile_name}' loaded: {profile.description}")
                print(f"   Sources: {profile.sources}")
            else:
                print(f"❌ Profile '{profile_name}' not found")
                return False

        # Test IOC type filtering
        ip_profiles = pm.get_profiles_for_ioc_type('ip')
        if any(p.name == 'IP-basic' for p in ip_profiles):
            print("✅ IOC type filtering works")
        else:
            print("❌ IOC type filtering failed")
            return False

        return True

    except Exception as e:
        print(f"❌ Profile system error: {e}")
        traceback.print_exc()
        return False

def test_enrichment_sources():
    """Test enrichment source implementations"""
    print("\n🔍 Testing enrichment sources...")

    try:
        from app.iris_engine.enrichment.sources import SOURCES

        # Test source registry
        expected_sources = ['abuseipdb', 'greynoise', 'virustotal', 'talos']

        for source_name in expected_sources:
            if source_name in SOURCES:
                source_class = SOURCES[source_name]
                source = source_class()
                print(f"✅ Source '{source_name}' initialized: {source.description}")
                print(f"   Supports: {list(source.ioc_support)}")

                # Test basic functionality (without API calls)
                if source.supports_ioc_type('ip'):
                    print(f"   ✅ Supports IP addresses")

            else:
                print(f"❌ Source '{source_name}' not found in registry")
                return False

        return True

    except Exception as e:
        print(f"❌ Source testing error: {e}")
        traceback.print_exc()
        return False

def test_normalizer():
    """Test the data normalizer"""
    print("\n🔍 Testing data normalizer...")

    try:
        from app.iris_engine.enrichment.normalizer import EnrichmentNormalizer

        normalizer = EnrichmentNormalizer()
        print("✅ Normalizer initialized")

        # Test with mock data
        mock_results = {
            'abuseipdb': {
                'ip': '8.8.8.8',
                'abuse_confidence': 85,
                'country_code': 'US',
                'isp': 'Google'
            },
            'greynoise': {
                'ip': '8.8.8.8',
                'classification': 'benign',
                'noise': False
            },
            'failed_source': {
                '_error': 'API timeout'
            }
        }

        normalized = normalizer.normalize('ip', '8.8.8.8', mock_results)

        # Validate structure
        required_fields = ['ioc', 'summary', 'sources', 'errors', 'metadata']
        for field in required_fields:
            if field not in normalized:
                print(f"❌ Missing field '{field}' in normalized data")
                return False

        print(f"✅ Normalized data structure valid")
        print(f"   Risk score: {normalized['summary']['risk_score']}")
        print(f"   Risk level: {normalized['summary']['risk_level']}")
        print(f"   Sources succeeded: {len(normalized['metadata']['sources_succeeded'])}")
        print(f"   Sources failed: {len(normalized['metadata']['sources_failed'])}")

        return True

    except Exception as e:
        print(f"❌ Normalizer error: {e}")
        traceback.print_exc()
        return False

def test_markdown_renderer():
    """Test the markdown report generator"""
    print("\n🔍 Testing markdown renderer...")

    try:
        from app.iris_engine.enrichment.markdown_renderer import MarkdownRenderer
        from app.iris_engine.enrichment.normalizer import EnrichmentNormalizer

        renderer = MarkdownRenderer()
        normalizer = EnrichmentNormalizer()
        print("✅ Markdown renderer initialized")

        # Create mock normalized data
        mock_results = {
            'abuseipdb': {
                'ip': '1.2.3.4',
                'abuse_confidence': 75,
                'country_code': 'US'
            }
        }

        normalized = normalizer.normalize('ip', '1.2.3.4', mock_results)

        # Test report generation
        report = renderer.render_enrichment_report(normalized, 'IP-basic', ['artifact-123'])

        if len(report) > 100 and '# IOC Enrichment Report' in report:
            print("✅ Full report generated successfully")
            print(f"   Report length: {len(report)} characters")
        else:
            print("❌ Report generation failed")
            return False

        # Test update block
        update_block = renderer.render_update_block(normalized, 'IP-basic')
        if '## 🔄 Update' in update_block:
            print("✅ Update block generated successfully")
        else:
            print("❌ Update block generation failed")
            return False

        return True

    except Exception as e:
        print(f"❌ Markdown renderer error: {e}")
        traceback.print_exc()
        return False

def test_integration():
    """Test integration between components"""
    print("\n🔍 Testing component integration...")

    try:
        from app.iris_engine.enrichment.profiles import get_profile
        from app.iris_engine.enrichment.sources import SOURCES
        from app.iris_engine.enrichment.normalizer import EnrichmentNormalizer
        from app.iris_engine.enrichment.markdown_renderer import MarkdownRenderer

        # Get a profile
        profile = get_profile('IP-basic')
        if not profile:
            print("❌ Could not load IP-basic profile")
            return False

        # Simulate enrichment workflow
        ioc_value = '8.8.8.8'
        mock_results = {}

        # "Execute" each source in the profile
        for source_name in profile.sources:
            if source_name in SOURCES:
                # Mock successful result
                mock_results[source_name] = {
                    'ioc_value': ioc_value,
                    'status': 'success',
                    '_source': source_name
                }
            else:
                # Mock failed result
                mock_results[source_name] = {
                    '_error': f'Source {source_name} not implemented'
                }

        # Normalize results
        normalizer = EnrichmentNormalizer()
        normalized = normalizer.normalize(profile.ioc_type, ioc_value, mock_results)

        # Generate report
        renderer = MarkdownRenderer()
        report = renderer.render_enrichment_report(normalized, profile.name)

        print(f"✅ Full workflow completed successfully")
        print(f"   Profile: {profile.name}")
        print(f"   Sources: {len(profile.sources)}")
        print(f"   Results: {len(mock_results)}")
        print(f"   Report size: {len(report)} characters")

        return True

    except Exception as e:
        print(f"❌ Integration test error: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Phase 1 IOC Enrichment Tests\n")

    tests = [
        ("Import Tests", test_imports),
        ("Profile System", test_profile_system),
        ("Enrichment Sources", test_enrichment_sources),
        ("Data Normalizer", test_normalizer),
        ("Markdown Renderer", test_markdown_renderer),
        ("Component Integration", test_integration)
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\n{'='*50}")
        print(f"Running: {test_name}")
        print('='*50)

        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ Test '{test_name}' crashed: {e}")
            traceback.print_exc()
            results.append((test_name, False))

    # Summary
    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print('='*50)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! Phase 1 implementation is working correctly.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())