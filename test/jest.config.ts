import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
    preset: 'ts-jest',
    rootDir: '..',
    testMatch: ['<rootDir>/test/**/*.spec.ts'],
    testEnvironment: 'node',
    collectCoverage: true,
    collectCoverageFrom: ['<rootDir>/src/**/*.ts'],
    coverageDirectory: '<rootDir>/coverage',
    coverageReporters: ['lcovonly'],
    globals: {
        'ts-jest': {
            tsconfig: '<rootDir>/test/tsconfig.test.json'
        }
    }
};

export default config;
