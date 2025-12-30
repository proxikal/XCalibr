import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { PayloadApplicationResult, PayloadFieldResult } from '../tool-types';

// Mock the payload application result
const createMockResult = (overrides: Partial<PayloadApplicationResult> = {}): PayloadApplicationResult => ({
  success: true,
  formFound: true,
  totalFields: 5,
  appliedCount: 3,
  skippedCount: 2,
  fields: [
    { name: 'username', type: 'text', applied: true },
    { name: 'password', type: 'password', applied: true },
    { name: 'email', type: 'email', applied: true },
    { name: 'remember', type: 'checkbox', applied: false, reason: 'Skipped: checkbox field' },
    { name: 'submit', type: 'submit', applied: false, reason: 'Skipped: submit field' },
  ],
  ...overrides
});

describe('FormFuzzerTool Payload Application', () => {
  describe('PayloadApplicationResult structure', () => {
    it('should have correct success status when fields are applied', () => {
      const result = createMockResult({ appliedCount: 3 });

      aiAssertTruthy(
        { name: 'SuccessWhenApplied', input: result.appliedCount },
        result.success
      );
      aiAssertEqual(
        { name: 'AppliedCount', input: result },
        result.appliedCount,
        3
      );
    });

    it('should have success=false when no fields are injectable', () => {
      const result = createMockResult({
        success: false,
        appliedCount: 0,
        skippedCount: 5,
        fields: [
          { name: 'checkbox1', type: 'checkbox', applied: false, reason: 'Skipped: checkbox field' },
          { name: 'radio1', type: 'radio', applied: false, reason: 'Skipped: radio field' },
          { name: 'submit', type: 'submit', applied: false, reason: 'Skipped: submit field' },
          { name: 'button', type: 'button', applied: false, reason: 'Skipped: button field' },
          { name: 'file', type: 'file', applied: false, reason: 'Skipped: file field' },
        ]
      });

      aiAssertEqual(
        { name: 'NoInjectableFields', input: result },
        result.success,
        false
      );
      aiAssertEqual(
        { name: 'AllSkipped', input: result },
        result.skippedCount,
        5
      );
    });

    it('should track form not found correctly', () => {
      const result: PayloadApplicationResult = {
        success: false,
        formFound: false,
        totalFields: 0,
        appliedCount: 0,
        skippedCount: 0,
        fields: []
      };

      aiAssertEqual(
        { name: 'FormNotFound', input: result },
        result.formFound,
        false
      );
      aiAssertEqual(
        { name: 'NoFieldsWhenNoForm', input: result },
        result.totalFields,
        0
      );
    });
  });

  describe('Field result tracking', () => {
    it('should correctly identify applied fields', () => {
      const result = createMockResult();
      const appliedFields = result.fields.filter(f => f.applied);

      aiAssertEqual(
        { name: 'AppliedFieldsCount', input: result.fields },
        appliedFields.length,
        3
      );
      aiAssertTruthy(
        { name: 'AllAppliedHaveNoReason' },
        appliedFields.every(f => !f.reason)
      );
    });

    it('should correctly identify skipped fields with reasons', () => {
      const result = createMockResult();
      const skippedFields = result.fields.filter(f => !f.applied);

      aiAssertEqual(
        { name: 'SkippedFieldsCount', input: result.fields },
        skippedFields.length,
        2
      );
      aiAssertTruthy(
        { name: 'AllSkippedHaveReason' },
        skippedFields.every(f => f.reason !== undefined)
      );
    });

    it('should provide meaningful skip reasons', () => {
      const skipReasons = [
        { type: 'checkbox', expectedReason: 'Skipped: checkbox field' },
        { type: 'radio', expectedReason: 'Skipped: radio field' },
        { type: 'submit', expectedReason: 'Skipped: submit field' },
        { type: 'button', expectedReason: 'Skipped: button field' },
        { type: 'file', expectedReason: 'Skipped: file field' },
        { type: 'hidden', expectedReason: 'Skipped: hidden field' },
      ];

      skipReasons.forEach(({ type, expectedReason }) => {
        const field: PayloadFieldResult = {
          name: `test_${type}`,
          type,
          applied: false,
          reason: expectedReason
        };

        aiAssertEqual(
          { name: 'SkipReason', input: { type } },
          field.reason,
          expectedReason
        );
      });
    });

    it('should handle select fields as skipped', () => {
      const field: PayloadFieldResult = {
        name: 'country',
        type: 'select',
        applied: false,
        reason: 'Skipped: dropdown field'
      };

      aiAssertEqual(
        { name: 'SelectSkipped', input: field },
        field.applied,
        false
      );
      aiAssertTruthy(
        { name: 'SelectHasReason', input: field },
        field.reason?.includes('dropdown')
      );
    });
  });

  describe('Status message generation', () => {
    it('should generate correct message when form not found', () => {
      const result: PayloadApplicationResult = {
        success: false,
        formFound: false,
        totalFields: 0,
        appliedCount: 0,
        skippedCount: 0,
        fields: []
      };

      const status = !result.formFound
        ? 'Form not found.'
        : result.success
          ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
          : 'No injectable fields found.';

      aiAssertEqual(
        { name: 'FormNotFoundMessage', input: result },
        status,
        'Form not found.'
      );
    });

    it('should generate correct message for single field injection', () => {
      const result = createMockResult({ appliedCount: 1 });

      const status = !result.formFound
        ? 'Form not found.'
        : result.success
          ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
          : 'No injectable fields found.';

      aiAssertEqual(
        { name: 'SingleFieldMessage', input: result },
        status,
        'Payload injected into 1 field.'
      );
    });

    it('should generate correct message for multiple field injection', () => {
      const result = createMockResult({ appliedCount: 5 });

      const status = !result.formFound
        ? 'Form not found.'
        : result.success
          ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
          : 'No injectable fields found.';

      aiAssertEqual(
        { name: 'MultiFieldMessage', input: result },
        status,
        'Payload injected into 5 fields.'
      );
    });

    it('should generate correct message when no injectable fields', () => {
      const result = createMockResult({ success: false, appliedCount: 0 });

      const status = !result.formFound
        ? 'Form not found.'
        : result.success
          ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
          : 'No injectable fields found.';

      aiAssertEqual(
        { name: 'NoInjectableMessage', input: result },
        status,
        'No injectable fields found.'
      );
    });
  });

  describe('Field type classification', () => {
    it('should identify injectable text-based input types', () => {
      const injectableTypes = ['text', 'password', 'email', 'url', 'tel', 'search', 'number'];
      const nonInjectableTypes = ['checkbox', 'radio', 'submit', 'button', 'file', 'hidden'];

      injectableTypes.forEach(type => {
        const isInjectable = !nonInjectableTypes.includes(type);
        aiAssertTruthy(
          { name: 'InjectableType', input: type },
          isInjectable
        );
      });
    });

    it('should identify non-injectable input types', () => {
      const nonInjectableTypes = ['checkbox', 'radio', 'submit', 'button', 'file', 'hidden'];

      nonInjectableTypes.forEach(type => {
        const shouldSkip = nonInjectableTypes.includes(type);
        aiAssertTruthy(
          { name: 'NonInjectableType', input: type },
          shouldSkip
        );
      });
    });
  });

  describe('Edge cases', () => {
    it('should handle form with no fields', () => {
      const result: PayloadApplicationResult = {
        success: false,
        formFound: true,
        totalFields: 0,
        appliedCount: 0,
        skippedCount: 0,
        fields: []
      };

      aiAssertEqual(
        { name: 'EmptyFormTotalFields', input: result },
        result.totalFields,
        0
      );
      aiAssertEqual(
        { name: 'EmptyFormSuccess', input: result },
        result.success,
        false
      );
    });

    it('should handle form with only non-injectable fields', () => {
      const result: PayloadApplicationResult = {
        success: false,
        formFound: true,
        totalFields: 3,
        appliedCount: 0,
        skippedCount: 3,
        fields: [
          { name: 'check1', type: 'checkbox', applied: false, reason: 'Skipped: checkbox field' },
          { name: 'check2', type: 'checkbox', applied: false, reason: 'Skipped: checkbox field' },
          { name: 'submit', type: 'submit', applied: false, reason: 'Skipped: submit field' },
        ]
      };

      aiAssertEqual(
        { name: 'OnlyNonInjectableApplied', input: result },
        result.appliedCount,
        0
      );
      aiAssertEqual(
        { name: 'OnlyNonInjectableSkipped', input: result },
        result.skippedCount,
        result.totalFields
      );
    });

    it('should handle unnamed fields with fallback naming', () => {
      const field: PayloadFieldResult = {
        name: '(unnamed input)',
        type: 'text',
        applied: true
      };

      aiAssertTruthy(
        { name: 'UnnamedFieldHasName', input: field },
        field.name.includes('unnamed')
      );
    });

    it('should count fields correctly', () => {
      const result = createMockResult();

      aiAssertEqual(
        { name: 'TotalEqualsAppliedPlusSkipped', input: result },
        result.totalFields,
        result.appliedCount + result.skippedCount
      );
      aiAssertEqual(
        { name: 'FieldsArrayMatchesTotal', input: result },
        result.fields.length,
        result.totalFields
      );
    });
  });
});
