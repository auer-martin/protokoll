import assert from 'assert';
import { describe, it } from 'node:test';

import { appendFragmentParams, appendQueryParams } from './request-utils.js';

void describe('core utils', () => {
  void describe('appendQueryParams', () => {
    void it('appends query params (no query, no fragment)', () => {
      const url = appendQueryParams({
        url: new URL('http://example.com'),
        params: { hello: 'world' },
      });

      assert.strictEqual(url.href, 'http://example.com/?hello=world');
    });

    void it('appends query params (query, no fragment)', () => {
      const url = appendQueryParams({
        url: new URL('http://example.com/?harry=potter'),
        params: { hello: 'world' },
      });

      assert.strictEqual(
        url.href,
        'http://example.com/?harry=potter&hello=world'
      );
    });

    void it('appends query params (query, fragment)', () => {
      const url = appendQueryParams({
        url: new URL('http://example.com/?harry=potter#1234'),
        params: { hello: 'world' },
      });

      assert.strictEqual(
        url.href,
        'http://example.com/?harry=potter&hello=world#1234'
      );
    });
  });

  void describe('appendFragmentParams', () => {
    void it('appends fragment params (no query, no fragment)', () => {
      const url = appendFragmentParams({
        url: new URL('http://example.com'),
        fragments: { hello: 'world' },
      });

      assert.strictEqual(url.href, 'http://example.com/#hello=world');
    });

    void it('appends fragment params (query, no fragment)', () => {
      const url = appendFragmentParams({
        url: new URL('http://example.com/?harry=potter'),
        fragments: { hello: 'world' },
      });

      assert.strictEqual(
        url.href,
        'http://example.com/?harry=potter#hello=world'
      );
    });

    void it('appends query params (query, fragment)', () => {
      const url = appendFragmentParams({
        url: new URL('http://example.com/?harry=potter#1234'),
        fragments: { hello: 'world' },
      });

      assert.strictEqual(
        url.href,
        'http://example.com/?harry=potter#1234=&hello=world'
      );
    });
  });
});
