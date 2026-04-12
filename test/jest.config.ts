import type { Config } from '@jest/types';
import { createDefaultPreset } from 'ts-jest';

const config: Config.InitialOptions = {
    preset: 'ts-jest',
    rootDir: '..',
    testMatch: ['<rootDir>/test/**/*.spec.ts'],
    testEnvironment: 'node',
    collectCoverage: true,
    collectCoverageFrom: ['<rootDir>/src/**/*.ts'],
    coverageDirectory: '<rootDir>/coverage',
    coverageReporters: ['lcovonly'],
    testTimeout: 60000,
    ...createDefaultPreset()
};

export default config;
