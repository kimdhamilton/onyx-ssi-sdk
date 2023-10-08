/** @type {import('@ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    testMatch: ['**/tests/**/?(*.)+(spec|test).[jt]s?(x)'],
    testPathIgnorePatterns: ["hardhat"],
    testTimeout: 60000,
    coverageReporters: [
        ['lcov', { projectRoot: '../' }],
        'text-summary',
    ],
    transform: {
        '^.+\\.(js|ts)$': 'babel-jest',
    },
    transformIgnorePatterns: ["/node_modules/(?!key-did-resolver|pkh-did-resolver/)"]
};
